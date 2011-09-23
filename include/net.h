#ifndef __NET_H__
#define __NET_H__

#include <sys/socket.h>
#include "proto.h"

struct co_buffer {
	int offset;
	int len;
	char *buf;
};

int do_read(int sockfd, void *buf, int len);
int do_writev(int sockfd, struct iovec *iov, int len, int offset);
void do_co_read(struct co_buffer *cob, void *buf, size_t count);
int connect_to(const char *name, int port, int idle, int intvl, int cnt);
int create_listen_ports(int port, int (*callback)(int fd, void *), void *data);

int set_nonblocking(int fd);
int set_nodelay(int fd);
int set_cork(int fd);
int unset_cork(int fd);
int set_keepalive(int fd,int idle, int intvl, int cnt);

#endif
