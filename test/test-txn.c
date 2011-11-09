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

static void test_txn_list_cb(struct acrd_handle *h, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static void test_txn_setup(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_txn_list_cb,
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

static void test_txn_teardown(struct acrd_fixture *fixture, gconstpointer p)
{
	acrd_close(fixture->handle);
}

static void test_txn_multi_write(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata[32];
	uint32_t retdata_len;
	int ret;
	struct acrd_tx *tx;

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_write(tx, "/tmp/0", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/1", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data));
	g_assert_cmpstr(retdata, ==, data);
	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/1", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data));
	g_assert_cmpstr(retdata, ==, data);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_write(tx, "/tmp/0", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/2", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_EXIST);
	acrd_tx_close(tx);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_write(tx, "/tmp/2", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/1", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_EXIST);
	acrd_tx_close(tx);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_write(tx, "/tmp/3", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/3", data, sizeof(data), 0,
			   ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_EXIST);
	acrd_tx_close(tx);
}

static void test_txn_multi_read(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	char retdata1[32], retdata2[32];
	uint32_t retdata1_len, retdata2_len;
	int ret;
	struct acrd_tx *tx;

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_write(h, "/tmp/1", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	retdata1_len = sizeof(retdata1);
	ret = acrd_tx_read(tx, "/tmp/0", retdata1, &retdata1_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	retdata2_len = sizeof(retdata2);
	ret = acrd_tx_read(tx, "/tmp/1", retdata2, &retdata2_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	g_assert(retdata1_len == sizeof(data));
	g_assert_cmpstr(data, ==, retdata1);
	g_assert(retdata2_len == sizeof(data));
	g_assert_cmpstr(data, ==, retdata2);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	retdata2_len = sizeof(retdata1);
	ret = acrd_tx_read(tx, "/tmp/2", retdata1, &retdata1_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	retdata2_len = sizeof(retdata2);
	ret = acrd_tx_read(tx, "/tmp/1", retdata2, &retdata2_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	acrd_tx_close(tx);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	retdata1_len = sizeof(retdata1);
	ret = acrd_tx_read(tx, "/tmp/0", retdata1, &retdata1_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	retdata2_len = sizeof(retdata2);
	ret = acrd_tx_read(tx, "/tmp/2", retdata2, &retdata2_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	acrd_tx_close(tx);
}

static void test_txn_update_if_exists(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "data";
	const char newdata[] = "newdata";
	char retdata[32];
	uint32_t retdata_len;
	int ret;
	struct acrd_tx *tx;

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_del(tx, "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/0", newdata, sizeof(newdata), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	acrd_tx_close(tx);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_del(tx, "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/0", newdata, sizeof(newdata), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(newdata));
	g_assert_cmpstr(retdata, ==, newdata);
}

static void test_txn_increment(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data[] = "3";
	const char newdata[] = "4";
	char retdata[32];
	uint32_t retdata_len;
	int ret;
	struct acrd_tx *tx;

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_cmp(tx, "/tmp/0", data, sizeof(data), 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/0", newdata, sizeof(newdata), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	acrd_tx_close(tx);

	ret = acrd_write(h, "/tmp/0", data, sizeof(data), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_cmp(tx, "/tmp/0", data, sizeof(data), 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/0", newdata, sizeof(newdata), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(newdata));
	g_assert_cmpstr(retdata, ==, newdata);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_cmp(tx, "/tmp/0", data, sizeof(data), 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_write(tx, "/tmp/0", newdata, sizeof(newdata), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTEQUAL);
	acrd_tx_close(tx);
}

static void test_txn_ainc(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	uint32_t data = 5555;
	uint32_t newdata = 5556;
	uint32_t *readdata;
	uint32_t delta = 1;
	char retdata[32];
	uint32_t retdata_len = sizeof(data);
	int ret;
	struct acrd_tx *tx;

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_atomic_inc(tx, "/tmp/0", &delta, sizeof(uint32_t), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	acrd_tx_close(tx);

	ret = acrd_write(h, "/tmp/0", &data, sizeof(uint32_t), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_atomic_inc(tx, "/tmp/0", &delta, sizeof(uint32_t), 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	ret = acrd_read(h, "/tmp/0", &retdata, &retdata_len, 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	readdata = (uint32_t *)retdata;
	g_assert(*readdata == newdata);
}

static void test_txn_merge(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data1";
	const char data2[] = "data2";
	int ret;
	struct acrd_tx *tx;

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_write(h, "/tmp/1", data1, sizeof(data1), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_write(h, "/tmp/2", data2, sizeof(data2), 0, ACRD_FLAG_CREATE);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_scmp(tx, "/tmp/0", "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_del(tx, "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	ret = acrd_del(h, "/tmp/1", 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_scmp(tx, "/tmp/0", "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_del(tx, "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTFOUND);
	acrd_tx_close(tx);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_scmp(tx, "/tmp/0", "/tmp/2", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_del(tx, "/tmp/2", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_NOTEQUAL);
	acrd_tx_close(tx);
}

static void test_txn_swap(struct acrd_fixture *fixture, gconstpointer p)
{
	struct acrd_handle *h = fixture->handle;
	const char data1[] = "data1";
	const char data2[] = "data2";
	int ret;
	struct acrd_tx *tx;
	char retdata[32];
	uint32_t retdata_len;

	ret = acrd_write(h, "/tmp/0", data1, sizeof(data1), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_write(h, "/tmp/1", data2, sizeof(data2), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_copy(tx, "/tmp/0", "/tmp/2", ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_copy(tx, "/tmp/1", "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_copy(tx, "/tmp/2", "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_del(tx, "/tmp/2", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_SUCCESS);
	acrd_tx_close(tx);

	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/0", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data2));
	g_assert_cmpstr(retdata, ==, data2);
	retdata_len = sizeof(retdata);
	ret = acrd_read(h, "/tmp/1", retdata, &retdata_len, 0, 0);
	g_assert(ret == ACRD_SUCCESS);
	g_assert(retdata_len == sizeof(data1));
	g_assert_cmpstr(retdata, ==, data1);

	ret = acrd_write(h, "/tmp/2", data1, sizeof(data1), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);

	tx = acrd_tx_init(h);
	g_assert(tx != NULL);
	ret = acrd_tx_copy(tx, "/tmp/0", "/tmp/2", ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_copy(tx, "/tmp/1", "/tmp/0", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_copy(tx, "/tmp/2", "/tmp/1", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_del(tx, "/tmp/2", 0);
	g_assert(ret == ACRD_SUCCESS);
	ret = acrd_tx_commit(tx, 0);
	g_assert(ret == ACRD_ERR_EXIST);
	acrd_tx_close(tx);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add("/txn/multi_write", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_multi_write, test_txn_teardown);
	g_test_add("/txn/multi_read", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_multi_read, test_txn_teardown);
	g_test_add("/txn/update_if_exists", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_update_if_exists, test_txn_teardown);
	g_test_add("/txn/increment", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_increment, test_txn_teardown);
	g_test_add("/txn/merge", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_merge, test_txn_teardown);
	g_test_add("/txn/swap", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_swap, test_txn_teardown);
	g_test_add("/txn/ainc", struct acrd_fixture, NULL,
		   test_txn_setup, test_txn_ainc, test_txn_teardown);

	return g_test_run();
}
