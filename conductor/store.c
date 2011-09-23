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
#include <memory.h>
#include <db.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>

#include "accord.h"
#include "store.h"
#include "logger.h"
#include "util.h"

static DB *dbp;
static DB_ENV *envp;
static DB_MPOOLFILE *mpf;

#define LOG_DIR_NAME "log"
#define DB_FILE_NAME "accord.db"

int store_init(const char *rootdir, int in_memory_mode)
{
	int ret;
	uint32_t env_flags = DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG |
		DB_INIT_MPOOL | DB_INIT_TXN;
	uint32_t flags =  DB_CREATE | DB_AUTO_COMMIT | DB_DIRTY_READ;
	char dbpath[PATH_MAX];
	char logpath[PATH_MAX];

	/* TODO: decide procedure whether an in_memory_mode is specified or not */
	if (rootdir[0] != '/')
		return -1;

	snprintf(dbpath, sizeof(dbpath), "%s/"DB_FILE_NAME, rootdir);
	snprintf(logpath, sizeof(logpath), "%s/"LOG_DIR_NAME, rootdir);

	/* FIXME : set permission correctly */
	ret = mkdir(rootdir, 0777);
	if (ret != 0) {
		if (errno == EEXIST)
			;
		else {
			eprintf("creating dir %p failed.\n", dbpath);
			goto failed;
		}
	}

	ret = mkdir(logpath, 0777);
	if (ret != 0) {
		if (errno == EEXIST)
			;
		else {
			eprintf("creating logpath %p is failed.\n", logpath);
			goto failed;
		}
	}

	ret = db_env_create(&envp, 0);
	if (ret != 0) {
		eprintf("db_env_create failed.\n");
		goto failed;
	}

	if (in_memory_mode) {
		envp->set_flags(envp, DB_LOG_IN_MEMORY, 1);
		/* FIXME : make this value configurable */
		envp->set_cachesize(envp, 4, 1, 1);

		env_flags |= DB_PRIVATE;
	}

	/* FIXME : make this value configurable */
	envp->set_lg_bsize(envp, 1024*1024*1024);
	envp->set_lk_max_locks(envp, 4096);
	envp->set_lk_max_objects(envp, 4096);
	envp->set_lk_max_lockers(envp, 4096);
	envp->set_lk_partitions(envp, 1024);
	ret = envp->open(envp, logpath, env_flags, 0);
	if (ret != 0) {
		eprintf("DB_ENV->open %p failed.\n", logpath);
		goto failed;
	}

	/* setup a DB */
	ret = db_create(&dbp, envp, 0);
	if (ret != 0) {
		eprintf("%s\n", db_strerror(ret));
		return -1;
	}

	dbp->set_pagesize(dbp, 65536);
	ret = dbp->set_flags(dbp, DB_TXN_NOT_DURABLE);
	if (in_memory_mode) {
		mpf = dbp->get_mpf(dbp);
		mpf->set_flags(mpf, DB_MPOOL_NOFILE, 1);
	}

	if (ret != 0) {
		eprintf("db_set_flags failed.\n");
		goto failed;
	}

	if (in_memory_mode)
		ret = dbp->open(dbp, NULL, NULL, NULL, DB_BTREE, flags, 0664);
	else
		ret = dbp->open(dbp, NULL, dbpath, NULL, DB_BTREE, flags, 0664);
	if (ret != 0) {
		eprintf("db_open failed.\n");
		goto failed;
	}

	return 0;
failed:
	dbp->err(dbp, ret, "%s", dbpath);
	dbp->close(dbp, 0);
	return -1;
}

int store_read(const char *key, void **data, uint32_t *data_len,
	       uint64_t offset, struct acrd_txid *txid)
{
	DBT db_key, db_data;
	int ret;
	DB_TXN *tid = NULL;

	if (txid)
		tid = txid->tid;

	memset(&db_key, 0, sizeof(db_key));
	memset(&db_data, 0, sizeof(db_data));

	db_key.data = (void *)key;
	db_key.size = strlen(key) + 1;

	db_data.doff = offset;
	db_data.dlen = *data_len;
	db_data.flags = DB_DBT_PARTIAL;

	ret = dbp->get(dbp, tid, &db_key, &db_data, DB_DIRTY_READ);
	if (ret != 0) {
		switch (ret) {
		case DB_NOTFOUND:
			return ACRD_ERR_NOTFOUND;
		default:
			dbp->err(dbp, ret, "DB->get");
			return ACRD_ERR_UNKNOWN;
		}
	}

	if (data)
		*data = db_data.data;

	*data_len = db_data.size;

	return ACRD_SUCCESS;
}

static int store_exists(const char *key, struct acrd_txid *txid)
{
	DBT db_key;
	int ret;
	DB_TXN *tid = NULL;

	if (txid)
		tid = txid->tid;

	memset(&db_key, 0, sizeof(db_key));

	db_key.data = (void *)key;
	db_key.size = strlen(key) + 1;

	ret = dbp->exists(dbp, tid, &db_key, 0);
	if (ret == 0)
		return 1;
	if (ret == DB_NOTFOUND)
		return 0;
	else {
		dbp->err(dbp, ret, "DB->exists");
		return 0;
	}
}

int store_write(const char *key, const void *data, uint32_t data_len,
		uint64_t offset, uint32_t flags, struct acrd_txid *txid)
{
	DBT db_key, db_data, db_tmp;
	int ret;
	uint32_t db_flags = 0;
	DB_TXN *tid = NULL;

	if (flags & ACRD_FLAG_CREATE) {
		if (flags & ACRD_FLAG_EXCL)
			db_flags = DB_NOOVERWRITE;
	} else if (!store_exists(key, txid))
		return ACRD_ERR_NOTFOUND;

	if (txid)
		tid = txid->tid;

	memset(&db_key, 0, sizeof(db_key));
	memset(&db_data, 0, sizeof(db_data));
	memset(&db_tmp, 0, sizeof(db_data));

	db_key.data = (void *)key;
	db_key.size = strlen(key) + 1;

	db_data.data = (void *)data;
	db_data.doff = offset;
	db_data.dlen = data_len;
	db_data.size = data_len;
	db_data.flags = DB_DBT_PARTIAL;

	if (flags & ACRD_FLAG_APPEND) {
		ret = dbp->get(dbp, tid, &db_key, &db_tmp, 0);
		if (ret != DB_NOTFOUND && ret != 0) {
			dbp->err(dbp, ret, "DB->get");
			return ACRD_ERR_UNKNOWN;
		}

		db_data.doff = db_tmp.size;
	}

	ret = dbp->put(dbp, tid, &db_key, &db_data, db_flags);
	if (ret != 0) {
		switch (ret) {
		case DB_KEYEXIST:
			return ACRD_ERR_EXIST;
		default:
			dbp->err(dbp, ret, "DB->put");
			return ACRD_ERR_UNKNOWN;
		}
	}

	return ACRD_SUCCESS;
}

int store_writev(struct store_req_vec *vec, int nr)
{
	DBT db_key;
	int ret;
	size_t buf_size = 0;
	static char *buf;
	void *opaque;
	int i;

	for (i = 0; i < nr; i++)
		buf_size += strlen(vec[i].key) + vec[i].data_len + 256;

	buf = malloc(buf_size);

	memset(&db_key, 0, sizeof(db_key));

	db_key.ulen = buf_size;
	db_key.data = buf;
	db_key.flags = DB_DBT_USERMEM;

	DB_MULTIPLE_WRITE_INIT(opaque, &db_key);

	for (i = 0; i < nr; i++)
		DB_MULTIPLE_KEY_WRITE_NEXT(opaque, &db_key, vec[i].key,
					   strlen(vec[i].key) + 1, vec[i].data,
					   vec[i].data_len);

	ret = dbp->put(dbp, NULL, &db_key, NULL, DB_MULTIPLE_KEY);
	if (ret != 0) {
		switch (ret) {
		default:
			dbp->err(dbp, ret, "DB->put");
			return ACRD_ERR_UNKNOWN;
		}
	}

	free(buf);

	return ACRD_SUCCESS;
}

int store_sync(void)
{
	return envp->memp_sync(envp, 0);
}

int store_del(const char *key, struct acrd_txid *txid)
{
	DBT db_key;
	int ret;
	DB_TXN *tid = NULL;

	if (txid)
		tid = txid->tid;

	memset(&db_key, 0, sizeof(db_key));

	db_key.data = (void *)key;
	db_key.size = strlen(key) + 1;

	ret = dbp->del(dbp, tid, &db_key, 0);
	if (ret != 0) {
		switch (ret) {
		case DB_NOTFOUND:
			return ACRD_ERR_NOTFOUND;
		default:
			dbp->err(dbp, ret, "DB->del");
			return ACRD_ERR_UNKNOWN;
		}
	}

	return ACRD_SUCCESS;
}

int store_list(const char *key, int (*add_file)(const char *, void *),
	       void *opaque, struct acrd_txid *txid)
{
	DBT db_key, db_data;
	int ret;
	DB_TXN *tid = NULL;
	DBC *cursor;

	if (txid)
		tid = txid->tid;

	ret = dbp->cursor(dbp, tid, &cursor, DB_DIRTY_READ);
	if (ret) {
		eprintf("failed open a cursor\n");
		return ACRD_ERR_UNKNOWN;
	}

	memset(&db_key, 0, sizeof(db_key));
	memset(&db_data, 0, sizeof(db_data));

	if (key) {
		db_key.data = (void *)key;
		db_key.size = strlen(key) + 1;

		ret = cursor->c_get(cursor, &db_key, &db_data, DB_SET_RANGE);
	} else
		ret = cursor->c_get(cursor, &db_key, &db_data, DB_FIRST);

	while (ret == 0) {
		if (key && strncmp(db_key.data, key, strlen(key)) != 0)
			/* prefix doesn't match */
			break;

		ret = add_file(db_key.data, opaque);
		if (ret != 0)
			break;

		ret = cursor->c_get(cursor, &db_key, &db_data, DB_NEXT);
	};

	if (ret == 0 || ret == DB_NOTFOUND)
		ret = ACRD_SUCCESS;
	else {
		envp->err(envp, ret, "store_list failed\n");
		ret = ACRD_ERR_UNKNOWN;
	}

	cursor->close(cursor);

	return ret;
}

int store_tx_begin(struct acrd_txid *tx)
{
	uint32_t flags = DB_TXN_NOSYNC | DB_DIRTY_READ;
	int ret;
	DB_TXN *tid;

	ret = envp->txn_begin(envp, NULL, &tid, flags);
	if (ret != 0) {
		envp->err(envp, ret, "tx_begin failed\n");
		return -1;
	}

	tx->tid = tid;
	dprintf("tid : %p\n", tid);

	return ret;
}

int store_tx_commit(struct acrd_txid *tx)
{
	int ret;
	DB_TXN *tid = tx->tid;

	dprintf("tid : %p\n", tid);
	ret = tid->commit(tid, 0);

	if (ret != 0) {
		envp->err(envp, ret, "DB_TXN->commit failed\n");
		return -1;
	}

	return 0;
}

int store_tx_abort(struct acrd_txid *tx)
{
	int ret;
	DB_TXN *tid = tx->tid;

	dprintf("tid : %p\n", tid);
	ret = tid->abort(tid);
	if (ret != 0) {
		envp->err(envp, ret, "DB_TXN->abort failed\n");
		eprintf("DB_TXN->abort failed\n");
		return -1;
	}

	return 0;
}

int store_close(void)
{
	dbp->close(dbp, 0);
	envp->close(envp, 0);

	return 0;
}
