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
#include <unistd.h>
#include <pthread.h>

#include "list.h"
#include "util.h"
#include "work.h"

static LIST_HEAD(work_queue_list);

struct work_queue {
	struct list_head worker_queue_siblings;

	pthread_cond_t pending_cond;
	pthread_mutex_t pending_lock;
	struct list_head q;
	work_func_t fn;
	int interval;

	int stop;

	pthread_t worker_thread;
};

void queue_work(struct work_queue *wq, struct list_head *w_list)
{
	pthread_mutex_lock(&wq->pending_lock);

	list_add_tail(w_list, &wq->q);

	pthread_mutex_unlock(&wq->pending_lock);

	pthread_cond_signal(&wq->pending_cond);
}

static void *worker_routine(void *arg)
{
	struct work_queue *wq = arg;
	struct list_head list;

	while (!wq->stop) {
		if (wq->interval)
			usleep(wq->interval * 1000);

		pthread_mutex_lock(&wq->pending_lock);
retest:
		if (wq->stop) {
			pthread_mutex_unlock(&wq->pending_lock);
			pthread_exit(NULL);
		}

		if (list_empty(&wq->q)) {
			pthread_cond_wait(&wq->pending_cond, &wq->pending_lock);
			goto retest;
		}

		INIT_LIST_HEAD(&list);
		list_splice_init(&wq->q, &list);

		pthread_mutex_unlock(&wq->pending_lock);

		if (!list_empty(&list))
			wq->fn(&list);
	}

	pthread_exit(NULL);
}

struct work_queue *init_work_queue(work_func_t fn, int interval)
{
	int ret;
	struct work_queue *wq;

	wq = zalloc(sizeof(*wq));
	if (!wq)
		return NULL;

	wq->fn = fn;
	wq->interval = interval;
	INIT_LIST_HEAD(&wq->q);

	pthread_cond_init(&wq->pending_cond, NULL);

	pthread_mutex_init(&wq->pending_lock, NULL);

	ret = pthread_create(&wq->worker_thread, NULL, worker_routine, wq);
	if (ret) {
		fprintf(stderr, "failed to create a worker thread, %s\n",
			strerror(ret));
		goto destroy_threads;
	}

	list_add(&wq->worker_queue_siblings, &work_queue_list);

	return wq;
destroy_threads:
	wq->stop = 1;

	pthread_join(wq->worker_thread, NULL);

	/* destroy_cond_mutex: */
	pthread_cond_destroy(&wq->pending_cond);
	pthread_mutex_destroy(&wq->pending_lock);

	return NULL;
}

void exit_work_queue(struct work_queue *wq)
{
	pthread_mutex_lock(&wq->pending_lock);
	wq->stop = 1;
	pthread_mutex_unlock(&wq->pending_lock);
	pthread_cond_broadcast(&wq->pending_cond);

	pthread_join(wq->worker_thread, NULL);

	pthread_cond_destroy(&wq->pending_cond);
	pthread_mutex_destroy(&wq->pending_lock);

	wq->stop = 0;
}
