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

#include "accord.h"
#include "util.h"
#include "list.h"

struct acrd_fixture {
	struct acrd_handle *handle;
};

struct acrd_path_list_entry {
	char *path;

	struct list_head list;
};

static void test_watch_list_cb(struct acrd_handle *h, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static void test_watch_setup(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_watch_list_cb,
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

	fixture->handle = h;
}

static void test_watch_teardown(struct acrd_fixture *fixture, gconstpointer p)
{
	acrd_close(fixture->handle);
}

static void test_watch_cb(struct acrd_handle *bh, struct acrd_watch_info *info,
			  void *arg)
{
	struct acrd_watch_info **retdata = arg;

	g_assert(*retdata == NULL);
	*retdata = info;
}

static void test_watch_add_and_rm(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	struct acrd_watch_info *info1, *info2, *info3;
	int ret;

	info1 = acrd_add_watch(h, "/tmp/0", ACRD_EVENT_ALL, test_watch_cb, NULL);
	g_assert(info1 != NULL);

	info2 = acrd_add_watch(h, "/tmp/0", ACRD_EVENT_ALL, test_watch_cb, NULL);
	g_assert(info2 != NULL);

	info3 = acrd_add_watch(h, "/tmp/0", ACRD_EVENT_ALL, test_watch_cb, NULL);
	g_assert(info3 != NULL);

	ret = acrd_rm_watch(h, info3);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_rm_watch(h, info1);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_rm_watch(h, info1);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	ret = acrd_rm_watch(h, info2);
	g_assert(ret == ACRD_SUCCESS);

	free(info1);
	free(info2);
	free(info3);
}

static void test_watch_created(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	struct acrd_watch_info *info, *retdata = NULL;
	const char data1[] = "data1";
	const char data2[] = "data2";
	int ret;

	info = acrd_add_watch(h, "/tmp/0", ACRD_EVENT_ALL, test_watch_cb, &retdata);
	g_assert(info != NULL);
	g_assert(retdata == NULL);

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->events == ACRD_EVENT_CREATED);

	retdata = NULL;
	ret = acrd_write(h, "/tmp/0", data2, sizeof(data2), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_ERR_EXIST);
	g_assert(retdata == NULL);

	ret = acrd_rm_watch(h, info);
	g_assert(ret == ACRD_SUCCESS);

	free(info);
}

static void test_watch_deleted(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	struct acrd_watch_info *info, *retdata = NULL;
	const char data[] = "data";
	int ret;

	info = acrd_add_watch(h, "/tmp/0", ACRD_EVENT_ALL, test_watch_cb, &retdata);
	g_assert(info != NULL);
	g_assert(retdata == NULL);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata = NULL;
	ret = acrd_del(h, "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->events == ACRD_EVENT_DELETED);

	retdata = NULL;
	ret = acrd_del(h, "/tmp/0", 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	g_assert(retdata == NULL);

	ret = acrd_rm_watch(h, info);
	g_assert(ret == ACRD_SUCCESS);

	free(info);
}

static void test_watch_changed(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	struct acrd_watch_info *info, *retdata = NULL;
	const char data[] = "data";
	int ret;

	info = acrd_add_watch(h, "/tmp/0", ACRD_EVENT_ALL, test_watch_cb, &retdata);
	g_assert(info != NULL);
	g_assert(retdata == NULL);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata = NULL;
	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->offset == 0);
	g_assert(info->events == ACRD_EVENT_CHANGED);

	retdata = NULL;
	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 3, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->offset == 3);
	g_assert(info->events == ACRD_EVENT_CHANGED);

	ret = acrd_rm_watch(h, info);
	g_assert(ret == ACRD_SUCCESS);

	free(info);
}

static void test_watch_copied(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	struct acrd_watch_info *info, *retdata = NULL;
	const char data[] = "data";
	int ret;

	info = acrd_add_watch(h, "/tmp/1", ACRD_EVENT_ALL, test_watch_cb, &retdata);
	g_assert(info != NULL);
	g_assert(retdata == NULL);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata = NULL;
	ret = acrd_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->events == ACRD_EVENT_COPIED);

	retdata = NULL;
	ret = acrd_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->events == ACRD_EVENT_COPIED);

	retdata = NULL;
	ret = acrd_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_ERR_EXIST);
	g_assert(retdata == NULL);

	retdata = NULL;
	ret = acrd_copy(h, "/tmp/0", "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata == info);
	g_assert(info->events == ACRD_EVENT_COPIED);

	ret = acrd_rm_watch(h, info);
	g_assert(ret == ACRD_SUCCESS);

	free(info);
}

static void __test_watch_mask(struct acrd_handle *h, uint32_t mask)
{
	struct acrd_watch_info *info, *retdata = NULL;
	const char data[] = "data";
	int ret;

	info = acrd_add_watch(h, "/tmp/0", mask, test_watch_cb, &retdata);
	g_assert(info != NULL);
	g_assert(retdata == NULL);

	ret = acrd_write(h, "/tmp/1", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata = NULL;
	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	if (mask & ACRD_EVENT_CREATED) {
		g_assert(retdata == info);
		g_assert(info->events == ACRD_EVENT_CREATED);
	} else
		g_assert(retdata == NULL);

	retdata = NULL;
	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	if (mask & ACRD_EVENT_CHANGED) {
		g_assert(retdata == info);
		g_assert(info->events == ACRD_EVENT_CHANGED);
	} else
		g_assert(retdata == NULL);

	retdata = NULL;
	ret = acrd_del(h, "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	if (mask & ACRD_EVENT_DELETED) {
		g_assert(retdata == info);
		g_assert(info->events == ACRD_EVENT_DELETED);
	} else
		g_assert(retdata == NULL);

	retdata = NULL;
	ret = acrd_copy(h, "/tmp/1", "/tmp/0", ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	if (mask & ACRD_EVENT_COPIED) {
		g_assert(retdata == info);
		g_assert(info->events == ACRD_EVENT_COPIED);
	} else
		g_assert(retdata == NULL);

	retdata = NULL;
	ret = acrd_del(h, "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_del(h, "/tmp/1", 0);

	ret = acrd_rm_watch(h, info);
	g_assert(ret == ACRD_SUCCESS);

	free(info);
}

static void test_watch_mask(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;

	__test_watch_mask(h, ACRD_EVENT_CREATED);
	__test_watch_mask(h, ACRD_EVENT_CHANGED);
	__test_watch_mask(h, ACRD_EVENT_DELETED);
	__test_watch_mask(h, ACRD_EVENT_COPIED);

	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_CHANGED);
	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_DELETED);
	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_COPIED);
	__test_watch_mask(h, ACRD_EVENT_CHANGED | ACRD_EVENT_DELETED);
	__test_watch_mask(h, ACRD_EVENT_CHANGED | ACRD_EVENT_COPIED);
	__test_watch_mask(h, ACRD_EVENT_DELETED | ACRD_EVENT_COPIED);

	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_CHANGED | ACRD_EVENT_DELETED);
	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_CHANGED | ACRD_EVENT_COPIED);
	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_DELETED | ACRD_EVENT_COPIED);
	__test_watch_mask(h, ACRD_EVENT_CHANGED | ACRD_EVENT_DELETED | ACRD_EVENT_COPIED);

	__test_watch_mask(h, ACRD_EVENT_CREATED | ACRD_EVENT_CHANGED | ACRD_EVENT_DELETED | ACRD_EVENT_COPIED);
	__test_watch_mask(h, ACRD_EVENT_ALL);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add("/watch/add_and_rm", struct acrd_fixture, NULL,
		   test_watch_setup, test_watch_add_and_rm, test_watch_teardown);
	g_test_add("/watch/created", struct acrd_fixture, NULL,
		   test_watch_setup, test_watch_created, test_watch_teardown);
	g_test_add("/watch/deleted", struct acrd_fixture, NULL,
		   test_watch_setup, test_watch_deleted, test_watch_teardown);
	g_test_add("/watch/changed", struct acrd_fixture, NULL,
		   test_watch_setup, test_watch_changed, test_watch_teardown);
	g_test_add("/watch/copied", struct acrd_fixture, NULL,
		   test_watch_setup, test_watch_copied, test_watch_teardown);
	g_test_add("/watch/mask", struct acrd_fixture, NULL,
		   test_watch_setup, test_watch_mask, test_watch_teardown);

	return g_test_run();
}
