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
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <corosync/cpg.h>

#include "store.h"
#include "event.h"
#include "net.h"
#include "work.h"
#include "logger.h"
#include "acrd_priv.h"

#define MAX_EVENT_SIZE 4096
#define ACRD_DEFAULT_PORT 9090
#define DEFAULT_STORE_DIR "/tmp/accord"

static struct cpg_name group_name = { 7, "accord" };

static char program_name[] = "accord";
/* FIXME: default value for testing */
int keepidle = 1;
int keepintvl = 1;
int keepcnt = 2;

static struct option const long_options[] = {
	/* common options */
	{"port", required_argument, NULL, 'p'},
	{"foreground", no_argument, NULL, 'f'},
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},

	/* storage-related options */
	{"mem", no_argument, NULL, 'm'},

	/* keepalive-related options */
	{"keeptimeout", required_argument, NULL, 't'},
	{"keepintvl", required_argument, NULL, 'i'},
	{"keepcnt", required_argument, NULL, 'c'},

	{NULL, 0, NULL, 0},
};

static const char *short_options = "p:fl:dhmt:i:c:";

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("Usage: %s [OPTION] [PATH]\n", program_name);
		printf("\
Accord Daemon\n\
  -p, --port              specify the listen port number\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug             print debug messages\n\
  -m, --mem               run in an in-memory mode\n\
  -t, --keeptimeout       specify idle time of sending keepalive packet to\
  detect client failure\n\
  -i, --keeptintvl        specify the period of sending keepalive packet to\
  detect client failure\n\
  -c, --keepcnt           specify the count of retrying to send packet.\
  timeout value is : keeptimeout + keepintvl * keepcnt.\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(status);
}

int main(int argc, char *argv[])
{
	int ch, longindex;
	unsigned short port = ACRD_DEFAULT_PORT;
	int in_memory_mode = 0;
	int is_daemon = 1, is_debug = 0;
	const char *dir = DEFAULT_STORE_DIR;
	char logfile[PATH_MAX];

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'f':
			is_daemon = 0;
			break;
		case 'd':
			is_debug = 1;
			break;
		case 't':
			keepidle = atoi(optarg);
			break;
		case 'i':
			keepintvl = atoi(optarg);
			break;
		case 'c':
			keepcnt = atoi(optarg);
			break;
		case 'm':
			in_memory_mode = 1;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (optind != argc)
		dir = argv[optind];

	if (is_daemon && daemon(0, 0))
		exit(1);

	strncpy(logfile, dir, sizeof(logfile));
	strncat(logfile, "/bdr.log", sizeof(logfile) - strlen(logfile) - 1);
	if (log_init(program_name, LOG_SPACE_SIZE, is_daemon, is_debug, logfile))
		exit(1);

	/* TODO: add error handling and parsing arguments. */
	dprintf("start to init accord.\n");
	if (init_event(MAX_EVENT_SIZE) < 0) {
		eprintf("failed to epoll.\n");
		exit(1);
	}

	dprintf("init corosync.\n");
	if (init_cpg(&group_name) < 0) {
		eprintf("failed to init corosync/cpg.\n");
		exit(1);
	}

	if (init_acrd_work_queue(in_memory_mode) != 0) {
		eprintf("failed to init work queue.\n");
		exit(1);
	}

	dprintf("initdb.\n");
	if (store_init(dir, in_memory_mode) < 0) {
		eprintf("failed to init berkeley db."
			"make sure that directory permission %s is correct"
			"and PATH is specified in absolute path.\n", dir);
		exit(1);
	}

	dprintf("create listen port.\n");
	if (create_listen_port(port, NULL)) {
		eprintf("failed to listen.\n");
		exit(1);
	}

	event_loop(-1);

	dprintf("exit.\n");
	return 0;
}
