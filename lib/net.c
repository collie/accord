/*
 * Copyright (C) 2011 MORITA Kazutaka <morita.kazutaka@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <coroutine.h>

#include "proto.h"
#include "util.h"
#include "event.h"
#include "net.h"

int create_listen_ports(int port, int (*callback)(int fd, void *), void *data)
{
	char servname[64];
	int fd, ret, opt;
	int success = 0;
	struct addrinfo hints, *res, *res0;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(NULL, servname, &hints, &res0);
	if (ret) {
		fprintf(stderr, "unable to get address info, %m\n");
		return 1;
	}

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		opt = 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
				 sizeof(opt));
		if (ret)
			fprintf(stderr, "can't set SO_REUSEADDR, %m\n");

		opt = 1;
		if (res->ai_family == AF_INET6) {
			ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
					 sizeof(opt));
			if (ret) {
				close(fd);
				continue;
			}
		}

		ret = bind(fd, res->ai_addr, res->ai_addrlen);
		if (ret) {
			fprintf(stderr, "can't bind server socket, %m\n");
			close(fd);
			continue;
		}

		ret = listen(fd, SOMAXCONN);
		if (ret) {
			fprintf(stderr, "can't listen to server socket, %m\n");
			close(fd);
			continue;
		}

		ret = set_nonblocking(fd);
		if (ret < 0) {
			close(fd);
			continue;
		}

		ret = callback(fd, data);
		if (ret) {
			close(fd);
			continue;
		}

		success++;
	}

	freeaddrinfo(res0);

	if (!success)
		fprintf(stderr, "can't create a listen fd\n");

	return !success;
}

int connect_to(const char *name, int port, int idle, int intvl, int cnt)
{
	char buf[64];
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int fd, ret;
	struct addrinfo hints, *res, *res0;
	struct linger linger_opt = {1, 0};

	memset(&hints, 0, sizeof(hints));
	snprintf(buf, sizeof(buf), "%d", port);

	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(name, buf, &hints, &res0);
	if (ret) {
		fprintf(stderr, "unable to get address info, %m\n");
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		ret = getnameinfo(res->ai_addr, res->ai_addrlen,
				  hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
				  NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger_opt,
				 sizeof(linger_opt));
		if (ret) {
			fprintf(stderr, "can't set SO_LINGER, %m\n");
			close(fd);
			continue;
		}

		ret = connect(fd, res->ai_addr, res->ai_addrlen);
		if (ret)
			fprintf(stderr, "failed to connect to %s:%d, %s\n",
					name, port, strerror(errno));
		else {
			ret = set_keepalive(fd, idle, intvl, cnt);
			if (ret)
				fprintf(stderr, "failed to set keepalives\n");
			else
				goto success;
		}

		close(fd);
	}
	fd = -1;
success:
	freeaddrinfo(res0);
	return fd;
}

int do_read(int sockfd, void *buf, int len)
{
	int rc, ret = 0;
reread:
	rc = read(sockfd, buf, len);
	if (rc == 0) {
		if (ret)
			return ret;
		else
			return -1;
	} else if (rc < 0) {
		if (errno == EINTR)
			goto reread;
		if (errno == EAGAIN)
			return ret;

		return -1;
	}

	len -= rc;
	ret += rc;
	buf = (char *)buf + rc;
	if (len)
		goto reread;

	return ret;
}

int do_writev(int sockfd, struct iovec *iov, int len, int offset)
{
	int ret, diff, iovcnt;
	struct iovec *last_iov;

	/* last_iov is inclusive, so count from one.  */
	iovcnt = 1;
	last_iov = iov;
	len += offset;

	while (last_iov->iov_len < len) {
		len -= last_iov->iov_len;

		last_iov++;
		iovcnt++;
	}

	diff = last_iov->iov_len - len;
	last_iov->iov_len -= diff;

	while (iov->iov_len <= offset) {
		offset -= iov->iov_len;

		iov++;
		iovcnt--;
	}

	iov->iov_base = (char *) iov->iov_base + offset;
	iov->iov_len -= offset;
again:
	ret = writev(sockfd, iov, iovcnt);
	if (ret == -1 && errno == EINTR)
		goto again;

	/* Undo the changes above */
	iov->iov_base = (char *) iov->iov_base - offset;
	iov->iov_len += offset;
	last_iov->iov_len += diff;
	return ret;
}

void do_co_read(struct co_buffer *cob, void *buf, size_t count)
{
	int done = 0, len;

	while (cob->offset + count > cob->len) {
		len = cob->len - cob->offset;
		memcpy(buf + done, cob->buf + cob->offset, len);

		done += len;
		count -= len;

		coroutine_yield();
	}

	memcpy(buf + done, cob->buf + cob->offset, count);
	cob->offset += count;
}


int set_nonblocking(int fd)
{
	int ret;

	ret = fcntl(fd, F_GETFL);
	if (ret < 0) {
		fprintf(stderr, "can't fcntl (F_GETFL), %m\n");
		close(fd);
	} else {
		ret = fcntl(fd, F_SETFL, ret | O_NONBLOCK);
		if (ret < 0)
			fprintf(stderr, "can't fcntl (O_NONBLOCK), %m\n");
	}

	return ret;
}

int set_nodelay(int fd)
{
	int ret, opt;

	opt = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	return ret;
}

int set_cork(int fd)
{
	int opt = 1;

	return setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

int unset_cork(int fd)
{
	int opt = 0;

	return setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

int set_keepalive(int fd, int idle, int intvl, int cnt)
{
	int ret, opt = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&opt, sizeof(opt));
	if (ret < 0)
		return ret;

	opt = idle;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&opt, sizeof(opt));
	if (ret < 0)
		return ret;

	opt = intvl;
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void*)&opt, sizeof(opt));
	if (ret < 0)
		return ret;

	opt = cnt;
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (void*)&opt, sizeof(opt));
	if (ret < 0)
		return ret;

	return ret;
}
