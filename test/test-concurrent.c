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

#include <glib.h>
#include <string.h>
#include <pthread.h>

#include "accord.h"
#include "util.h"
#include "coroutine.h"

#define NR_THREADS 100

static pthread_t acrd_threads[NR_THREADS];

struct acrd_path_list_entry {
	char *path;

	struct list_head list;
};

static void test_concurrent_list_cb(struct acrd_handle *h, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static void test_concurrent_setup(void)
{
	struct acrd_handle *h;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_concurrent_list_cb,
		.arg = &path_list,
	};
	struct acrd_path_list_entry *entry, *n;

	h = acrd_init("localhost", 9090, NULL, NULL, NULL);
	g_assert(h != NULL);

	/* cleanup */
	acrd_list(h, "/tmp/", 0, &listcb);
	list_for_each_entry_safe(entry, n, &path_list, list) {
		acrd_del(h, entry->path, 0);

		free(entry->path);
		list_del(&entry->list);
		free(entry);
	}

	acrd_close(h);
}

static pthread_mutex_t confchg_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t confchg_cond = PTHREAD_COND_INITIALIZER;

struct test_confchg_info {
	size_t nr_members;
	uint64_t members[NR_THREADS];
};

/*
 * check whether node id 'id' is included in 'members'
 */
static int is_member(uint64_t id, const uint64_t *members, size_t nr_members)
{
	int i;

	for (i = 0; i < nr_members; i++)
		if (members[i] == id)
			return 1;

	return 0;
}

static void test_join_fn(struct acrd_handle *bh, const uint64_t *member_list,
			 size_t member_list_entries, uint64_t nodeid, void *arg)
{
	static int signaled;
	struct test_confchg_info *info = arg;
	int i;

	g_assert(member_list_entries <= NR_THREADS);

	if (info->nr_members != 0) {
		g_assert(info->nr_members + 1 == member_list_entries);
		g_assert(is_member(nodeid, member_list, member_list_entries));
		for (i = 0; i < info->nr_members; i++)
			g_assert(is_member(info->members[i], member_list,
					   member_list_entries));
	} else
		/* there should be no duplication */
		for (i = 0; i < member_list_entries; i++)
			g_assert(!is_member(member_list[i], member_list + i + 1,
					    member_list_entries - i - 1));

	info->nr_members = member_list_entries;
	memcpy(info->members, member_list, sizeof(uint64_t) * info->nr_members);

	if (member_list_entries == NR_THREADS) {
		pthread_mutex_lock(&confchg_lock);
		if (signaled == 0) {
			/* the first thread starts leaving tests */
			signaled = 1;
			pthread_cond_signal(&confchg_cond);
		}
		pthread_mutex_unlock(&confchg_lock);
	}
}

static void test_leave_fn(struct acrd_handle *bh, const uint64_t *member_list,
			  size_t member_list_entries, uint64_t nodeid, void *arg)
{
	static int remaining_threads = NR_THREADS - 1;
	struct test_confchg_info *info = arg;
	int i;

	g_assert(0 <= member_list_entries);

	g_assert(info->nr_members - 1 == member_list_entries);
	g_assert(!is_member(nodeid, member_list, member_list_entries));
	g_assert(is_member(nodeid, info->members, info->nr_members));
	for (i = 0; i < member_list_entries; i++)
		g_assert(is_member(member_list[i], info->members,
				   info->nr_members));

	info->nr_members = member_list_entries;
	memcpy(info->members, member_list, sizeof(uint64_t) * info->nr_members);

	pthread_mutex_lock(&confchg_lock);
	if (remaining_threads == member_list_entries) {
		/* start stopping the next thread */
		pthread_cond_signal(&confchg_cond);
		remaining_threads--;
	}
	pthread_mutex_unlock(&confchg_lock);
}

static void *test_confchg_fn(void *arg)
{
	struct acrd_handle *h;
	struct test_confchg_info info = {0};

	h = acrd_init("localhost", 9090, test_join_fn, test_leave_fn, &info);
	g_assert(h != NULL);

	pthread_mutex_lock(&confchg_lock);

	/* sleep until all the threads connect to the accord server */
	pthread_cond_wait(&confchg_cond, &confchg_lock);

	pthread_mutex_unlock(&confchg_lock);

	acrd_close(h);

	pthread_exit(NULL);
}

static void test_concurrent_confchg(void)
{
	int i;

	test_concurrent_setup();

	for (i = 0; i < NR_THREADS; i++)
		pthread_create(acrd_threads + i, NULL, test_confchg_fn, NULL);

	for (i = 0; i < NR_THREADS; i++)
		pthread_join(acrd_threads[i], NULL);
}

static void *test_lock_fn(void *arg)
{
	struct acrd_handle *h;
	const char data[] = "data";
	int *ret = arg;

	h = acrd_init("localhost", 9090, NULL, NULL, NULL);
	g_assert(h != NULL);

	*ret = acrd_write(h, "/tmp/lock", data, sizeof(data), 0,
			 ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);

	acrd_close(h);

	pthread_exit(NULL);
}

static void test_concurrent_lock(void)
{
	int i, nr_success = 0, nr_exists = 0;
	int ret[NR_THREADS];

	test_concurrent_setup();

	for (i = 0; i < NR_THREADS; i++)
		pthread_create(acrd_threads + i, NULL, test_lock_fn, ret + i);

	for (i = 0; i < NR_THREADS; i++)
		pthread_join(acrd_threads[i], NULL);

	for (i = 0; i < NR_THREADS; i++) {
		if (ret[i] == ACRD_SUCCESS)
			nr_success++;
		else if (ret[i] == ACRD_ERR_EXIST)
			nr_exists++;
		else
			g_assert_not_reached();
	}

	/* only one thread can get a lock */
	g_assert(nr_success == 1);
	g_assert(nr_exists == NR_THREADS - 1);
}

static int test_queue_push(struct acrd_handle *h)
{
	struct acrd_tx *tx;
	char retdata[32];
	uint32_t size, max;
	int ret;
	char path[256];

	size = sizeof(retdata);
	ret = acrd_read(h, "/tmp/queue/max", retdata, &size, 0, 0);
	if (ret == ACRD_SUCCESS) {
		g_assert(size == sizeof(max));

		memcpy(&max, retdata, sizeof(max));
		g_assert(max > 0);

		sprintf(path, "/tmp/queue/%d", max + 1);

		tx = acrd_tx_init(h);
		acrd_tx_cmp(tx, "/tmp/queue/max", &max, sizeof(max), 0);
		max++;
		acrd_tx_write(tx, "/tmp/queue/max", &max, sizeof(max), 0, 0);
		acrd_tx_write(tx, path, &max, sizeof(max), 0,
			     ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);

		ret = acrd_tx_commit(tx, 0);

		acrd_tx_close(tx);
	} else if (ret == ACRD_ERR_NOTFOUND) {
		max = 1;

		sprintf(path, "/tmp/queue/%d", max);

		tx = acrd_tx_init(h);
		acrd_tx_write(tx, "/tmp/queue/min", &max, sizeof(max), 0,
			     ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
		acrd_tx_write(tx, "/tmp/queue/max", &max, sizeof(max), 0,
			     ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
		acrd_tx_write(tx, path, &max, sizeof(max), 0,
			     ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);

		ret = acrd_tx_commit(tx, 0);

		acrd_tx_close(tx);
	} else
		g_assert_not_reached();

	if (ret != ACRD_SUCCESS) {
		g_assert(ret == ACRD_ERR_NOTEQUAL || ret == ACRD_ERR_EXIST);
		return -1;
	}

	return 0;
}

static int test_queue_pop(struct acrd_handle *h)
{
	struct acrd_tx *tx;
	char retdata[32];
	uint32_t size, min;
	int ret;
	char path[256];

	size = sizeof(retdata);
	ret = acrd_read(h, "/tmp/queue/min", retdata, &size, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(size == sizeof(min));

	memcpy(&min, retdata, sizeof(min));
	g_assert(min > 0);

	sprintf(path, "/tmp/queue/%d", min);

	tx = acrd_tx_init(h);
	acrd_tx_cmp(tx, "/tmp/queue/min", &min, sizeof(min), 0);
	min++;
	acrd_tx_write(tx, "/tmp/queue/min", &min, sizeof(min), 0, 0);
	acrd_tx_del(tx, path, 0);

	ret = acrd_tx_commit(tx, 0);

	acrd_tx_close(tx);

	if (ret != ACRD_SUCCESS) {
		g_assert(ret == ACRD_ERR_NOTEQUAL);
		return -1;
	}

	return 0;
}

static void *test_queue_fn(void *arg)
{
	struct acrd_handle *h;

	h = acrd_init("localhost", 9090, NULL, NULL, NULL);
	g_assert(h != NULL);

	while (test_queue_push(h) != 0)
		;

	while (test_queue_pop(h) != 0)
		;

	while (test_queue_push(h) != 0)
		;

	while (test_queue_pop(h) != 0)
		;

	acrd_close(h);

	pthread_exit(NULL);
}

static void test_concurrent_queue(void)
{
	struct acrd_handle *h;
	int i, ret;
	char retdata[32];
	uint32_t size, min, max;

	test_concurrent_setup();

	for (i = 0; i < NR_THREADS; i++)
		pthread_create(acrd_threads + i, NULL, test_queue_fn, NULL);

	for (i = 0; i < NR_THREADS; i++)
		pthread_join(acrd_threads[i], NULL);


	h = acrd_init("localhost", 9090, NULL, NULL, NULL);
	g_assert(h != NULL);

	size = sizeof(retdata);
	ret = acrd_read(h, "/tmp/queue/max", retdata, &size, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(size == sizeof(max));

	memcpy(&max, retdata, sizeof(max));

	size = sizeof(retdata);
	ret = acrd_read(h, "/tmp/queue/max", retdata, &size, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(size == sizeof(min));

	memcpy(&min, retdata, sizeof(min));

	g_assert(max == 2 * NR_THREADS);
	g_assert(min == 2 * NR_THREADS);

	acrd_close(h);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/concurrent/confchg", test_concurrent_confchg);
	g_test_add_func("/concurrent/lock", test_concurrent_lock);
	g_test_add_func("/concurrent/queue", test_concurrent_queue);

	return g_test_run();
}
