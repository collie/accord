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

static void test_aio_list_cb(struct acrd_handle *h, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static void test_aio_setup(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_aio_list_cb,
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

static void test_aio_teardown(struct acrd_fixture *fixture, gconstpointer p)
{
	acrd_close(fixture->handle);
}

#define TEST_ACB_MAX 1000

static void test_aio_wait_cb(struct acrd_handle *h, struct acrd_aiocb *acb, void *arg)
{
	struct acrd_aiocb **acbs = arg;
	int i, expect = 1;

	for (i = 0; i < TEST_ACB_MAX; i++) {
		if (acbs[i] == acb)
			expect = 0;

		g_assert(acbs[i]->done == expect);
	}
}

static void test_aio_wait(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int i, ret;
	struct acrd_aiocb *acbs[TEST_ACB_MAX];


	for (i = 0; i < TEST_ACB_MAX; i++)
		acbs[i] = acrd_aio_setup(h, test_aio_wait_cb, acbs);

	for (i = 0; i < TEST_ACB_MAX; i++) {
		ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, 0, acbs[i]);
		g_assert(ret == ACRD_SUCCESS);
	}

	for (i = 0; i < TEST_ACB_MAX; i++) {
		acrd_aio_wait(h, acbs[i]);
		g_assert(acbs[i]->done == 1);
	}

	for (i = 0; i < TEST_ACB_MAX; i++)
		acrd_aio_release(h, acbs[i]);
}

static void test_aio_flush(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int i, ret;
	struct acrd_aiocb *acbs[TEST_ACB_MAX];

	for (i = 0; i < TEST_ACB_MAX; i++)
		acbs[i] = acrd_aio_setup(h, test_aio_wait_cb, acbs);

	for (i = 0; i < TEST_ACB_MAX; i++) {
		ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, 0, acbs[i]);
		g_assert(ret == ACRD_SUCCESS);
	}

	acrd_aio_flush(h);
	for (i = 0; i < TEST_ACB_MAX; i++) {
		g_assert(acbs[i]->done == 1);
		acrd_aio_release(h, acbs[i]);
	}
}

static void test_aio_cb(struct acrd_handle *h, struct acrd_aiocb *acb, void *arg)
{
	uint32_t *result = arg;

	*result = acb->result;
}

static void test_aio_create(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;
	struct acrd_aiocb *acb1, *acb2;
	uint32_t res1, res2;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_SUCCESS);
	g_assert(res2 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
}

static void test_aio_write(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "newdata";
	char retdata[32];
	uint32_t retdata_len;
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3, *acb4;
	uint32_t res1, res2, res3, res4;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data1, sizeof(data1), 0, 0, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data1, sizeof(data1), 0, ACRD_FLAG_CREATE, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	ret = acrd_aio_write(h, "/tmp/0", data2, sizeof(data2), 0, 0, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acb4 = acrd_aio_setup(h, test_aio_cb, &res4);
	retdata_len = sizeof(retdata);
	ret = acrd_aio_read(h, "/tmp/0", retdata, &retdata_len, 0, 0, acb4);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_ERR_NOTFOUND);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	g_assert(res4 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
	acrd_aio_release(h, acb4);

	g_assert(retdata_len == sizeof(data2));
	g_assert_cmpstr(retdata, ==, data2);
}

static void test_aio_partial_write(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3;
	uint32_t res1, res2, res3;
	char retdata[32];
	uint32_t retdata_len;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 2, 0, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	retdata_len = sizeof(retdata);
	ret = acrd_aio_read(h, "/tmp/0", retdata, &retdata_len, 0, 0, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_SUCCESS);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	g_assert(retdata_len == 7);
	g_assert_cmpstr(retdata, ==, "dadata");
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
}

static void test_aio_sync(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "newdata";
	char retdata[32];
	uint32_t retdata_len;
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3, *acb4;
	uint32_t res1, res2, res3, res4;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data1, sizeof(data1), 0,
			    ACRD_FLAG_SYNC, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data1, sizeof(data1), 0,
			    ACRD_FLAG_SYNC | ACRD_FLAG_CREATE, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	ret = acrd_aio_write(h, "/tmp/0", data2, sizeof(data2), 0,
			    ACRD_FLAG_SYNC, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acb4 = acrd_aio_setup(h, test_aio_cb, &res4);
	retdata_len = sizeof(retdata);
	ret = acrd_aio_read(h, "/tmp/0", retdata, &retdata_len, 0,
			    ACRD_FLAG_SYNC, acb4);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_ERR_NOTFOUND);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	g_assert(res4 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
	acrd_aio_release(h, acb4);

	g_assert(retdata_len == sizeof(data2));
	g_assert_cmpstr(retdata, ==, data2);
}

static void test_aio_append(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "appended_data";
	const char data3[] = "dataappended_data";
	char retdata1[32], retdata2[32];
	uint32_t retdata1_len, retdata2_len;
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3, *acb4, *acb5;
	uint32_t res1, res2, res3, res4, res5;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data1, sizeof(data1) - 1, 0, ACRD_FLAG_CREATE, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data2, sizeof(data2), 0, ACRD_FLAG_APPEND, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	retdata1_len = sizeof(retdata2);
	ret = acrd_aio_read(h, "/tmp/0", retdata1, &retdata1_len, 0, 0, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acb4 = acrd_aio_setup(h, test_aio_cb, &res4);
	ret = acrd_aio_write(h, "/tmp/1", data2, sizeof(data2), 0,
			    ACRD_FLAG_CREATE | ACRD_FLAG_APPEND, acb4);
	g_assert(ret == ACRD_SUCCESS);

	acb5 = acrd_aio_setup(h, test_aio_cb, &res5);
	retdata2_len = sizeof(retdata2);
	ret = acrd_aio_read(h, "/tmp/1", retdata2, &retdata2_len, 0, 0, acb5);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_SUCCESS);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	g_assert(res4 == ACRD_SUCCESS);
	g_assert(res5 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
	acrd_aio_release(h, acb4);
	acrd_aio_release(h, acb5);

	g_assert(retdata1_len == sizeof(data3));
	g_assert_cmpstr(retdata1, ==, data3);
	g_assert(retdata2_len == sizeof(data2));
	g_assert_cmpstr(retdata2, ==, data2);
}

static void test_aio_exclusive(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;
	struct acrd_aiocb *acb1, *acb2;
	uint32_t res1, res2;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0,
			    ACRD_FLAG_CREATE | ACRD_FLAG_EXCL, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0,
			    ACRD_FLAG_CREATE | ACRD_FLAG_EXCL, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_SUCCESS);
	g_assert(res2 == ACRD_ERR_EXIST);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
}

static void test_aio_read(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3;
	uint32_t res1, res2, res3;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	retdata_len = sizeof(retdata);
	ret = acrd_aio_read(h, "/tmp/0", retdata, &retdata_len, 0, 0, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	retdata_len = sizeof(retdata);
	ret = acrd_aio_read(h, "/tmp/0", retdata, &retdata_len, 0, 0, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_ERR_NOTFOUND);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);

	g_assert(retdata_len == sizeof(data));
	g_assert_cmpstr(retdata, ==, data);
}

static void test_aio_partial_read(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata1[32], retdata2[32], retdata3[32];
	uint32_t retdata1_len, retdata2_len, retdata3_len;
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3, *acb4;
	uint32_t res1, res2, res3, res4;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	retdata1_len = 2;
	ret = acrd_aio_read(h, "/tmp/0", retdata1, &retdata1_len, 1, 0, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	retdata2_len = sizeof(retdata2);
	ret = acrd_aio_read(h, "/tmp/0", retdata2, &retdata2_len, 3, 0, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acb4 = acrd_aio_setup(h, test_aio_cb, &res4);
	retdata3_len = sizeof(retdata3);
	ret = acrd_aio_read(h, "/tmp/0", retdata3, &retdata3_len, 100, 0, acb4);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_SUCCESS);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	g_assert(res4 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
	acrd_aio_release(h, acb4);

	g_assert(retdata1_len == 2);
	g_assert(retdata2_len == 2);
	g_assert(retdata3_len == 0);
	g_assert(memcmp(retdata1, "at", 2) == 0);
	g_assert_cmpstr(retdata2, ==, "a");
}

static void test_aio_del(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3;
	uint32_t res1, res2, res3;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_del(h, "/tmp/0", 0, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	ret = acrd_aio_del(h, "/tmp/0", 0, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_ERR_NOTFOUND);
	g_assert(res2 == ACRD_SUCCESS);
	g_assert(res3 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
}

static void test_aio_list(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_aio_list_cb,
		.arg = &path_list,
	};
	struct acrd_path_list_entry *entry, *n;
	const char *data[] = {"data1", "data2", "data3", "data4", "data5"};
	char path[64];
	int i, ret;
	struct acrd_aiocb *acb;
	uint32_t res;

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		sprintf(path, "/tmp/%d", i);
		ret = acrd_write(h, path, data[i], strlen(data[i]) + 1, 0, ACRD_FLAG_CREATE);
		g_assert(ret == ACRD_SUCCESS);
	}

	acb = acrd_aio_setup(h, test_aio_cb, &res);
	acrd_aio_list(h, NULL, 0, &listcb, acb);
	acrd_aio_wait(h, acb);
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

static void test_aio_prefix_search(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_aio_list_cb,
		.arg = &path_list,
	};
	struct acrd_path_list_entry *entry, *n;
	const char *data[] = {"data1", "data2", "data3", "data4", "data5"};
	char path[64];
	int i, ret;
	struct acrd_aiocb *acb;
	uint32_t res;

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

	acb = acrd_aio_setup(h, test_aio_cb, &res);
	acrd_aio_list(h, "/tmp/a", 0, &listcb, acb);
	acrd_aio_wait(h, acb);
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

static void test_aio_copy(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data";
	const char data2[] = "longer data";
	char retdata1[32], retdata2[32];
	uint32_t retdata1_len, retdata2_len;
	int ret;
	struct acrd_aiocb *acb1, *acb2, *acb3, *acb4, *acb5, *acb6, *acb7, *acb8, *acb9;
	uint32_t res1, res2, res3, res4, res5, res6, res7, res8, res9;

	acb1 = acrd_aio_setup(h, test_aio_cb, &res1);
	ret = acrd_aio_write(h, "/tmp/0", data1, sizeof(data1), 0, ACRD_FLAG_CREATE, acb1);
	g_assert(ret == ACRD_SUCCESS);

	acb2 = acrd_aio_setup(h, test_aio_cb, &res2);
	ret = acrd_aio_copy(h, "/tmp/0", "/tmp/1", 0, acb2);
	g_assert(ret == ACRD_SUCCESS);

	acb3 = acrd_aio_setup(h, test_aio_cb, &res3);
	ret = acrd_aio_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE, acb3);
	g_assert(ret == ACRD_SUCCESS);

	acb4 = acrd_aio_setup(h, test_aio_cb, &res4);
	ret = acrd_aio_copy(h, "/tmp/0", "/tmp/1", ACRD_FLAG_CREATE, acb4);
	g_assert(ret == ACRD_SUCCESS);

	acb5 = acrd_aio_setup(h, test_aio_cb, &res5);
	ret = acrd_aio_copy(h, "/tmp/0", "/tmp/1",
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL, acb5);
	g_assert(ret == ACRD_SUCCESS);

	acb6 = acrd_aio_setup(h, test_aio_cb, &res6);
	retdata1_len = sizeof(retdata1);
	ret = acrd_aio_read(h, "/tmp/1", retdata1, &retdata1_len, 0, 0, acb6);
	g_assert(ret == ACRD_SUCCESS);

	acb7 = acrd_aio_setup(h, test_aio_cb, &res7);
	ret = acrd_aio_write(h, "/tmp/2", data2, sizeof(data2), 0, ACRD_FLAG_CREATE, acb7);
	g_assert(ret == ACRD_SUCCESS);

	acb8 = acrd_aio_setup(h, test_aio_cb, &res8);
	ret = acrd_aio_copy(h, "/tmp/0", "/tmp/2", 0, acb8);
	g_assert(ret == ACRD_SUCCESS);

	acb9 = acrd_aio_setup(h, test_aio_cb, &res9);
	retdata2_len = sizeof(retdata2);
	ret = acrd_aio_read(h, "/tmp/2", retdata2, &retdata2_len, 0, 0, acb9);
	g_assert(ret == ACRD_SUCCESS);

	acrd_aio_flush(h);
	g_assert(res1 == ACRD_SUCCESS);
	g_assert(res2 == ACRD_ERR_NOTFOUND);
	g_assert(res3 == ACRD_SUCCESS);
	g_assert(res4 == ACRD_SUCCESS);
	g_assert(res5 == ACRD_ERR_EXIST);
	g_assert(res6 == ACRD_SUCCESS);
	g_assert(res7 == ACRD_SUCCESS);
	g_assert(res8 == ACRD_SUCCESS);
	g_assert(res9 == ACRD_SUCCESS);
	acrd_aio_release(h, acb1);
	acrd_aio_release(h, acb2);
	acrd_aio_release(h, acb3);
	acrd_aio_release(h, acb4);
	acrd_aio_release(h, acb5);
	acrd_aio_release(h, acb6);
	acrd_aio_release(h, acb7);
	acrd_aio_release(h, acb8);
	acrd_aio_release(h, acb9);

	g_assert(retdata1_len == sizeof(data1));
	g_assert_cmpstr(retdata1, ==, data1);
	g_assert(retdata2_len == sizeof(data1));
	g_assert_cmpstr(retdata2, ==, data1);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add("/aio/wait", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_wait, test_aio_teardown);
	g_test_add("/aio/flush", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_flush, test_aio_teardown);
	g_test_add("/aio/create", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_create, test_aio_teardown);
	g_test_add("/aio/write", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_write, test_aio_teardown);
	g_test_add("/aio/partial_write", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_partial_write, test_aio_teardown);
	g_test_add("/aio/sync", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_sync, test_aio_teardown);
	g_test_add("/aio/append", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_append, test_aio_teardown);
	g_test_add("/aio/exclusive", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_exclusive, test_aio_teardown);
	g_test_add("/aio/read", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_read, test_aio_teardown);
	g_test_add("/aio/partial_read", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_partial_read, test_aio_teardown);
	g_test_add("/aio/del", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_del, test_aio_teardown);
	g_test_add("/aio/list", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_list, test_aio_teardown);
	g_test_add("/aio/prefix_search", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_prefix_search, test_aio_teardown);
	g_test_add("/aio/copy", struct acrd_fixture, NULL,
		   test_aio_setup, test_aio_copy, test_aio_teardown);

	return g_test_run();
}
