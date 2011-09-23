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
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "event.h"
#include "coroutine.h"

static int efd;
static LIST_HEAD(events_list);

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct list_head ei_list;
};

int init_event(int nr)
{
	efd = epoll_create(nr);
	if (efd < 0) {
		fprintf(stderr, "can't create epoll fd\n");
		return -1;
	}
	return 0;
}

static struct event_info *lookup_event(int fd)
{
	struct event_info *ei;

	list_for_each_entry(ei, &events_list, ei_list) {
		if (ei->fd == fd)
			return ei;
	}
	return NULL;
}

int register_event(int fd, event_handler_t h, void *data)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = zalloc(sizeof(*ei));
	if (!ei)
		return -ENOMEM;

	ei->fd = fd;
	ei->handler = h;
	ei->data = data;

	ev.events = EPOLLIN;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		fprintf(stderr, "can't add epoll event, %m\n");
		free(ei);
	} else
		list_add(&ei->ei_list, &events_list);

	return ret;
}

void unregister_event(int fd)
{
	int ret;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei) {
		fprintf(stderr, "can't find a event\n");
		return;
	}

	ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret)
		fprintf(stderr, "can't del epoll event, %m\n");

	list_del(&ei->ei_list);
	free(ei);
}

int modify_event(int fd, unsigned int events)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei) {
		fprintf(stderr, "can't find event info %d\n", fd);
		return 1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		fprintf(stderr, "can't del epoll event, %m\n");
		return 1;
	}
	return 0;
}

void event_loop(int timeout)
{
	int i, nr;
	struct epoll_event events[128];

retry:
	nr = epoll_wait(efd, events, ARRAY_SIZE(events), timeout);
	if (nr < 0) {
		if (errno == EINTR)
			goto retry;
		fprintf(stderr, "epoll_wait failed, %m\n");
		exit(1);
	} else if (nr) {
		for (i = 0; i < nr; i++) {
			struct event_info *ei;

			ei = (struct event_info *)events[i].data.ptr;
			ei->handler(ei->fd, events[i].events, ei->data);
		}
	}
	goto retry;
}
