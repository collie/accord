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

static void test_io_list_cb(struct acrd_handle *h, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static void test_io_setup(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_io_list_cb,
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

static void test_io_teardown(struct acrd_fixture *fixture, gconstpointer p)
{
	acrd_close(fixture->handle);
}

static void test_io_create(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
}

static void test_io_write(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "newdata";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_write(h, "/tmp/0", data2, sizeof(data2), 0, 0);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data2));
	g_assert_cmpstr(retdata, ==, data2);
}

static void test_io_partial_write(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 2, 0);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == 7);
	g_assert_cmpstr(retdata, ==, "dadata");
}

static void test_io_sync(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "newdata";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	ret = acrd_write(h, "/tmp/0", data2, sizeof(data2), 0, ACRD_FLAG_SYNC);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_SYNC);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_write(h, "/tmp/0", data2, sizeof(data2), 0, ACRD_FLAG_SYNC);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, ACRD_FLAG_SYNC);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data2));
	g_assert_cmpstr(retdata, ==, data2);
}

static void test_io_append(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "appended_data";
	const char data3[] = "dataappended_data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1) - 1, 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_write(h, "/tmp/0", data2, sizeof(data2), 0, ACRD_FLAG_APPEND);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data3));
	g_assert_cmpstr(retdata, ==, data3);

	ret = acrd_write(h, "/tmp/1", data2, sizeof(data2), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_APPEND);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/1", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data2));
	g_assert_cmpstr(retdata, ==, data2);
}

static void test_io_exclusive(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_ERR_EXIST);
}

static void test_io_read(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data));
	g_assert_cmpstr(retdata, ==, data);
}

static void test_io_partial_read(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = 2;
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 1, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == 2);
	g_assert(memcmp(retdata, "at", 2) == 0);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 3, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == 2);
	g_assert_cmpstr(retdata, ==, "a");

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 100, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == 0);
}

static void test_io_del(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;

	ret = acrd_del(h, "/tmp/0", 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_del(h, "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
}

static void test_io_list(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_io_list_cb,
		.arg = &path_list,
	};
	struct acrd_path_list_entry *entry, *n;
	const char *data[] = {"data1", "data2", "data3", "data4", "data5"};
	char path[64];
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		sprintf(path, "/tmp/%d", i);
		ret = acrd_write(h, path, data[i], strlen(data[i]) + 1, 0,
				ACRD_FLAG_CREATE);
		g_assert(ret == ACRD_SUCCESS);
	}

	acrd_list(h, NULL, 0, &listcb);
	i = 0;
	list_for_each_entry_safe(entry, n, &path_list, list) {
		if (strncmp(entry->path, "/tmp/", strlen("/tmp/")) != 0) {
			g_test_message("db is not clean");
			continue;
		}
		g_assert(i < ARRAY_SIZE(data));
		sprintf(path, "/tmp/%d", i);
		g_assert_cmpstr(entry->path, ==, path);

		free(entry->path);
		list_del(&entry->list);
		free(entry);
		i++;
	}

	g_assert(i == ARRAY_SIZE(data));
}

static void test_io_prefix_search(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_io_list_cb,
		.arg = &path_list,
	};
	struct acrd_path_list_entry *entry, *n;
	const char *data[] = {"data1", "data2", "data3", "data4", "data5"};
	char path[64];
	int i, ret;

	ret = acrd_write(h, "/tmp/0", data[0], strlen(data[0]) + 1, 0, ACRD_FLAG_CREATE);
	ret = acrd_write(h, "/tmp/0a", data[0], strlen(data[0]) + 1, 0, ACRD_FLAG_CREATE);
	ret = acrd_write(h, "/tmp/0b", data[0], strlen(data[0]) + 1, 0, ACRD_FLAG_CREATE);
	ret = acrd_write(h, "/tmp/z", data[0], strlen(data[0]) + 1, 0, ACRD_FLAG_CREATE);
	ret = acrd_write(h, "/tmp/zc", data[0], strlen(data[0]) + 1, 0, ACRD_FLAG_CREATE);
	ret = acrd_write(h, "/tmp/zd", data[0], strlen(data[0]) + 1, 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	for (i = 0; i < ARRAY_SIZE(data); i++) {
		sprintf(path, "/tmp/a%d", i);
		ret = acrd_write(h, path, data[i], strlen(data[i]) + 1, 0, ACRD_FLAG_CREATE);
		g_assert(ret == ACRD_SUCCESS);
	}

	acrd_list(h, "/tmp/a", 0, &listcb);
	i = 0;
	list_for_each_entry_safe(entry, n, &path_list, list) {
		sprintf(path, "/tmp/a%d", i);
		g_assert_cmpstr(entry->path, ==, path);

		free(entry->path);
		list_del(&entry->list);
		free(entry);
		i++;
	}

	g_assert(i == ARRAY_SIZE(data));
}

static void test_io_copy(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "longer data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_copy(h, "/tmp/0", "/tmp/1", 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	ret = acrd_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_ERR_EXIST);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/1", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data1));
	g_assert_cmpstr(retdata, ==, data1);

	ret = acrd_write(h, "/tmp/2", data2, sizeof(data2), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	ret = acrd_copy(h, "/tmp/0", "/tmp/2", 0);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/2", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data1));
	g_assert_cmpstr(retdata, ==, data1);
}

static void test_io_large_data(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	uint8_t *data1, *data2;
	uint32_t retdata_len;
	int ret;
	const int data_size = 32 * 1024 * 1024; /* 32 MB */

	data1 = malloc(data_size);
	g_assert(data1);
	data2 = malloc(data_size);
	g_assert(data2);

	memset(data1, 0x5a, data_size);
	memset(data2, 0x00, data_size);

	ret = acrd_write(h, "/tmp/0", data1, data_size, 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	retdata_len = data_size;
	ret = acrd_read(h, "/tmp/0", data2, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == data_size);
	g_assert(memcmp(data1, data2, data_size) == 0);

	free(data1);
	free(data2);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add("/io/create", struct acrd_fixture, NULL,
		   test_io_setup, test_io_create, test_io_teardown);
	g_test_add("/io/write", struct acrd_fixture, NULL,
		   test_io_setup, test_io_write, test_io_teardown);
	g_test_add("/io/partial_write", struct acrd_fixture, NULL,
		   test_io_setup, test_io_partial_write, test_io_teardown);
	g_test_add("/io/sync", struct acrd_fixture, NULL,
		   test_io_setup, test_io_sync, test_io_teardown);
	g_test_add("/io/append", struct acrd_fixture, NULL,
		   test_io_setup, test_io_append, test_io_teardown);
	g_test_add("/io/exclusive", struct acrd_fixture, NULL,
		   test_io_setup, test_io_exclusive, test_io_teardown);
	g_test_add("/io/read", struct acrd_fixture, NULL,
		   test_io_setup, test_io_read, test_io_teardown);
	g_test_add("/io/partial_read", struct acrd_fixture, NULL,
		   test_io_setup, test_io_partial_read, test_io_teardown);
	g_test_add("/io/del", struct acrd_fixture, NULL,
		   test_io_setup, test_io_del, test_io_teardown);
	g_test_add("/io/list", struct acrd_fixture, NULL,
		   test_io_setup, test_io_list, test_io_teardown);
	g_test_add("/io/prefix_search", struct acrd_fixture, NULL,
		   test_io_setup, test_io_prefix_search, test_io_teardown);
	g_test_add("/io/copy", struct acrd_fixture, NULL,
		   test_io_setup, test_io_copy, test_io_teardown);
	g_test_add("/io/large_data", struct acrd_fixture, NULL,
		   test_io_setup, test_io_large_data, test_io_teardown);

	return g_test_run();
}
