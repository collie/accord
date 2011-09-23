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
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>

#include <accord.h>
#include "util.h"

#define dprintf(fmt, args...)						\
do {									\
	fprintf(stdout, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

static int total_n_handled;
static int total_n_launched;
static size_t total_n_bytes;
struct timeval total_time = {0, 0};

char *remotehost;
int n_threads;
int n_requests;
int msg_size;
int sync_mode;

char localhost[HOST_NAME_MAX];

struct request_info {
	struct timeval started;
	struct acrd_handle *bh;
};

static char *size_to_str(uint64_t _size, char *str, int str_size)
{
	const char *units[] = {"MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
	int i = 0;
	double size;

	size = (double)_size;
	size /= 1024 * 1024;
	while (i < ARRAY_SIZE(units) && size >= 1024) {
		i++;
		size /= 1024;
	}

	if (size >= 10)
		snprintf(str, str_size, "%.1lf %s", size, units[i]);
	else
		snprintf(str, str_size, "%.2lf %s", size, units[i]);

	return str;
}


static void bdrbench_aio_cb(struct acrd_handle *h, struct acrd_aiocb *acb, void *arg)
{
	int n_handled;

	if (acb->result != ACRD_SUCCESS)
		printf("%d\n", acb->result);

	__sync_add_and_fetch(&total_n_bytes, msg_size);
	n_handled = __sync_add_and_fetch(&total_n_handled, 1);
	if (n_handled && (n_handled % 10000) == 0)
		printf("%d requests done\n", n_handled);
}

static int launch_request(struct request_info *ri)
{
	char prefix[256], url[256];
	char *buf;
	int ret = -1, i, prefix_len;
	int tm;
	struct acrd_aiocb *acb;

	gettimeofday(&ri->started, NULL);
	buf = calloc(1, msg_size);
	memset(buf, 0xFF, msg_size);
	tm = (unsigned)time(NULL);

	prefix_len = sprintf(prefix, "/tmp/%s/%x/", localhost, tm);
	strcpy(url, prefix);

	for (i = 0; i < n_requests; i++) {
		sprintf(url + prefix_len, "%d", __sync_add_and_fetch(&total_n_launched, 1));

		acb = acrd_aio_setup(ri->bh, bdrbench_aio_cb, NULL);
	again:
		ret = acrd_aio_write(ri->bh, url, buf, msg_size, 0, ACRD_FLAG_CREATE | sync_mode, acb);
		if (ret != ACRD_SUCCESS) {
			if (ret == ACRD_ERR_AGAIN) {
				usleep(100000);
				goto again;
			}
			eprintf("err, %d\n", ret);
			exit(1);
		}
	}

	if (ret < 0) {
		eprintf("error\n");
		return -1;
	}

	acrd_aio_flush(ri->bh);
	return 0;
}

static void *th(void *p)
{
	struct request_info *ri;

	ri = malloc(sizeof(*ri));

	ri->bh = acrd_init(remotehost, 9090, NULL, NULL, NULL);
	if (!ri->bh) {
		eprintf("failed to initialize library\n");
		pthread_exit(NULL);
	}

	if (launch_request(ri) < 0)
		return NULL;

	return NULL;
}

int main(int argc, char *argv[])
{
	int i;
	pthread_t *threads;
	struct timeval start, end, total;
	double throughput;
	char s1[64], s2[64];

	if (argc < 6) {
		printf("usage: bdrbench [host] [n_threads] [n_reqs] "
			"[msg_size] [sync_mode]\n");
		return 1;
	}

	total_n_handled = 0;
	total_n_launched = 0;
	total_n_bytes = 0;

	gethostname(localhost, sizeof(localhost));

	setvbuf(stdout, NULL, _IONBF, 0);

	remotehost = argv[1];
	n_threads = atoi(argv[2]);
	n_requests = atoi(argv[3]);
	msg_size = atoi(argv[4]);
	if (!strcasecmp(argv[5], "nosync"))
		sync_mode = 0;
	else if (!strcasecmp(argv[5], "sync"))
		sync_mode = ACRD_FLAG_SYNC;
	else {
		fprintf(stderr, "sync mode must be \"nosync\" or \"sync\"\n");
		return 1;
	}

	gettimeofday(&start, NULL);

	threads = malloc(sizeof(*threads) * n_threads);
	for (i = 0; i < n_threads; i++)
		pthread_create(threads + i, NULL, th, NULL);

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);

	gettimeofday(&end, NULL);
	timersub(&end, &start, &total);

	if (!total_n_handled) {
		puts("Nothing worked.  You probably did something dumb.");
		return 0;
	}

	throughput = total_n_handled /
		(total.tv_sec + ((double)total.tv_usec)/1000000.0);

	printf("\n%d requests in %d.%06d sec. (%.2f throughput)\n"
	       "%s write. (%s/sec)\n",
	       total_n_handled, (int)total.tv_sec, (int)total.tv_usec,
	       throughput,
	       size_to_str(total_n_bytes, s1, sizeof(s1)),
	       size_to_str(1000000 * total_n_bytes / (1000000 * total.tv_sec + total.tv_usec), s2, sizeof(s2)));

	return 0;
}
