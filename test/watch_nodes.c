/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>

#include "accord.h"

static void join_cb(struct acrd_handle *bh, const uint64_t *memger_list,
		    size_t member_list_entries, uint64_t nodeid, void *arg)
{
	printf("node joined: %lx\n", nodeid);
}

static void leave_cb(struct acrd_handle *bh, const uint64_t *memger_list,
		     size_t member_list_entries, uint64_t nodeid, void *arg)
{
	printf("node left: %lx\n", nodeid);
}

/* test code */
int main(int argc, char *argv[])
{
	struct acrd_handle *bh;
	char *hostname;

	if (argc < 2) {
		printf("usage: watch_nodes [hostname]\n");
		return 1;
	}

	hostname = argv[1];
	bh = acrd_init(hostname, 9090, join_cb, leave_cb, NULL);

	while (1)
		sleep(1);

	acrd_close(bh);

	return 0;
}
