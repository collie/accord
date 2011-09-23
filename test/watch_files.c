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

static void watch_cb(struct acrd_handle *bh, struct acrd_watch_info *info, void *arg)
{
	printf("%s\n", info->path);
}

/* test code */
int main(int argc, char *argv[])
{
	struct acrd_handle *bh;
	uint32_t mask = ACRD_EVENT_ALL | ACRD_EVENT_PREFIX;
	char *hostname;
	struct acrd_watch_info *info;

	if (argc < 2) {
		printf("usage: watch_nodes [hostname]\n");
		return 1;
	}

	hostname = argv[1];
	bh = acrd_init(hostname, 9090, NULL, NULL, NULL);

	info = acrd_add_watch(bh, "", mask, watch_cb, NULL);

	while (1)
		sleep(1);

	acrd_close(bh);

	return 0;
}
