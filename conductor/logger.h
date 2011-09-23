/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * This code is based on log.h from Linux target framework (tgt).
 *   Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 */
#ifndef LOGGER_H
#define LOGGER_H

#include <sys/sem.h>
#include <sys/syslog.h>

#include "util.h"

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};

#define LOG_SPACE_SIZE (8 * 1024 * 1024)
#define MAX_MSG_SIZE 128

struct logmsg {
	short int prio;
	void *next;
	char *str;
};

struct logarea {
	int empty;
	int active;
	void *head;
	void *tail;
	void *start;
	void *end;
	char *buff;
	int semid;
	union semun semarg;
	int fd;
};

extern int log_init(const char *progname, int size, int daemon, int level,
		    const char *outfile);
extern void log_close (void);
extern void dump_logmsg (void *);
extern void log_write(int prio, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

extern int is_debug;

#define eprintf(fmt, args...)						\
do {									\
	log_write(LOG_ERR, "%s(%d) " fmt, __func__, __LINE__, ##args);	\
} while (0)

#define dprintf(fmt, args...)						\
do {									\
	if (unlikely(is_debug))						\
		log_write(LOG_DEBUG, "%s(%d) " fmt, __func__, __LINE__, ##args);\
} while (0)

#endif	/* LOG_H */
