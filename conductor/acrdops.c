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
#include <corosync/cpg.h>

#include "store.h"
#include "accord_proto.h"
#include "logger.h"
#include "util.h"
#include "acrd_priv.h"
#include "errno.h"

struct watcher {
	/* watching node name */
	char *path;
	uint32_t id;
	uint32_t mask;
	struct client_info *ci;
	struct list_head w_list;
};

static LIST_HEAD(watchers_list);

void remove_all_watch(struct client_info *ci)
{
	struct watcher *w, *wtmp;

	list_for_each_entry_safe(w, wtmp, &watchers_list, w_list) {
		if (w->ci == ci) {
			free(w->path);
			list_del(&w->w_list);
			free(w);
		}
	}
}

static int exec_write_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			  struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;
	const void *data;
	const char *path;
	uint32_t flags = req->flags;
	uint32_t size;
	const struct acrd_arg *path_arg, *data_arg;

	path_arg = get_arg(req, 0);
	data_arg = get_arg(req, 1);
	path = (char *)path_arg->data;
	data = data_arg->data;
	size = data_arg->size;

	if (likely(path && data))
		ret = store_write(path, data, size, req->offset, flags, txid);
	else
		ret = ACRD_ERR_UNKNOWN;

	if (rsp)
		(*rsp)->result = ret;

	return ret;
}

static void __exec_write_multi_reqs(struct acrd_rsp ***rsps, int *ret,
				    struct store_req_vec *vec, int nr)
{
	int i, rc;

	rc = store_writev(vec, nr);

	for (i = 0; i < nr; i++) {
		ret[i] = rc;
		if (rsps[i])
			(*rsps[i])->result = rc;
	}
}

static void exec_write_multi_reqs(const struct acrd_req **reqs, struct acrd_rsp ***rsps,
				  int *ret, size_t nr, struct acrd_txid *txid)
{
	int i, done;
	struct store_req_vec vec[MAX_MULTI_REQS];

	done = 0;
	for (i = 0; i < nr; i++) {
		if (reqs[i]->offset == 0 &&
		    (reqs[i]->flags & ~ACRD_FLAG_SYNC) == ACRD_FLAG_CREATE) {
			vec[i].key = (char *)get_arg(reqs[i], 0)->data;
			vec[i].data = get_arg(reqs[i], 1)->data;
			vec[i].data_len = get_arg(reqs[i], 1)->size;
			continue;
		}

		if (done < i)
			__exec_write_multi_reqs(rsps + done, ret + done,
						vec + done, i - done);

		ret[i] = exec_write_req(reqs[i], rsps[i], txid, NULL);
		done = i + 1;
	}
	if (done < i)
		__exec_write_multi_reqs(rsps + done, ret + done,
					vec + done, i - done);
}

static int exec_read_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			 struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;
	void *data;
	const char *path;
	uint32_t size;

	path = get_arg(req, 0)->data;
	size = req->size;

	if (likely(path))
		ret = store_read(path, &data, &size, req->offset, txid);
	else
		ret = ACRD_ERR_UNKNOWN;

	if (ret == ACRD_SUCCESS)
		*rsp = add_arg(*rsp, data, size);

	(*rsp)->result = ret;

	return ret;
}

static int exec_del_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;
	const char *path;

	path = get_arg(req, 0)->data;

	if (likely(path))
		ret = store_del(path, txid);
	else
		ret = ACRD_ERR_UNKNOWN;

	if (rsp)
		(*rsp)->result = ret;

	return ret;
}

static int exec_cmp_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;
	const char *path;
	void *data1;
	const void *data2;
	uint32_t count1, count2;
	const struct acrd_arg *path_arg, *data_arg;

	path_arg = get_arg(req, 0);
	data_arg = get_arg(req, 1);
	path = path_arg->data;
	data2 = data_arg->data;
	count2 = data_arg->size;

	count1 = UINT32_MAX; /* FIXME: handle data larger than UINT32_MAX */
	ret = store_read(path, &data1, &count1, 0, txid);
	if (ret != ACRD_SUCCESS) {
		dprintf("err when get p1\n");
		goto cleanup;
	}

	/* if size is different, no need to compare
	 * its contents.
	 */
	if (count1 != count2)
		ret = ACRD_ERR_NOTEQUAL;
	else if (memcmp(data1, data2, count1))
		ret = ACRD_ERR_NOTEQUAL;
	else
		ret = ACRD_SUCCESS;
cleanup:
	if (ret < 0)
		dprintf("err when cmp\n");

	if (rsp)
		(*rsp)->result = ret;

	return ret;
}

static int exec_scmp_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			 struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;
	const char *p1, *p2;
	void *buf, *d1 = NULL, *d2;
	uint32_t c1, c2;

	dprintf("scmp\n");
	p1 = get_arg(req, 0)->data;
	p2 = get_arg(req, 1)->data;

	c1 = UINT32_MAX; /* FIXME: handle data larger than UINT32_MAX */
	ret = store_read(p1, &buf, &c1, 0, txid);
	if (ret != ACRD_SUCCESS) {
		dprintf("err when get p1\n");
		goto cleanup;
	}
	/* the content of buf can be changed when we call db_get next
	 * time, so we need to preserve it here */
	d1 = malloc(c1);
	memcpy(d1, buf, c1);

	c2 = UINT32_MAX; /* FIXME: handle data larger than UINT32_MAX */
	ret = store_read(p2, &d2, &c2, 0, txid);
	if (ret != ACRD_SUCCESS) {
		dprintf("err when get p2\n");
		goto cleanup;
	}

	/* if size is different, no need to compare
	 * its contents.
	 */
	if (c1 != c2) {
		ret = ACRD_ERR_NOTEQUAL;
		goto cleanup;
	}

	if (memcmp(d1, d2, c1))
		ret = ACRD_ERR_NOTEQUAL;
	else
		ret = ACRD_SUCCESS;

cleanup:
	free(d1);
	if (ret < 0)
		eprintf("err when cmp\n");

	if (rsp)
		(*rsp)->result = ret;

	return ret;
}

static int exec_copy_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			 struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;
	const char *src, *dst;
	void *data;
	uint32_t count;

	src = get_arg(req, 0)->data;
	dst = get_arg(req, 1)->data;

	count = UINT32_MAX; /* FIXME: handle data larger than UINT32_MAX */
	ret = store_read(src, &data, &count, 0, txid);
	if (ret != ACRD_SUCCESS) {
		dprintf("err when copy\n");
		goto out;
	}

	if (!(req->flags & ACRD_FLAG_CREATE)) {
		/* delete existing key first */
		ret = store_del(dst, txid);
		if (ret != ACRD_SUCCESS) {
			dprintf("no such key %s\n", dst);
			goto out;
		}
	}
	ret = store_write(dst, data, count, 0, ACRD_FLAG_CREATE | req->flags, txid);
	if (ret != ACRD_SUCCESS)
		dprintf("err when copy\n");
out:
	if (rsp)
		(*rsp)->result = ret;

	return ret;
}

/*
 * returns the size of written buffer, -1 on error
 */
static int acrd_tx(const struct acrd_req *req,  struct acrd_rsp **rsp,
		  struct client_info *from)
{
	int ret;
	struct acrd_txid tx;
	struct acrd_op_tmpl *op;
	const struct acrd_req *child_req;
	const struct acrd_arg *arg;

	dprintf("%s\n", __func__);
	ret = store_tx_begin(&tx);
	if (ret < 0)
		return -1;

	dprintf("acrd_tx start.\n");
	for_each_arg(arg, req) {
		child_req = (const struct acrd_req *)arg->data;
		op = find_op(child_req->opcode);

		ret = op->exec_req(child_req, rsp, &tx, from);
		if (ret != ACRD_SUCCESS)
			goto cleanup;
	}

	ret = store_tx_commit(&tx);
	if (ret < 0) {
		ret = ACRD_ERR_UNKNOWN;
		goto cleanup;
	}

	dprintf("commited\n");
	return ret;
cleanup:
	store_tx_abort(&tx);
	if (rsp)
		(*rsp)->data_length = 0;;

	dprintf("aborted. ret %d\n", ret);

	return ret;
}

static int exec_tx_req(const struct acrd_req *req, struct acrd_rsp **rsp,
		       struct acrd_txid *txid, struct client_info *from)
{
	int ret = 0;

	ret = acrd_tx(req, rsp, from);

	if (rsp)
		(*rsp)->result = ret;

	return ret;
}

static int add_file_to_list(const char *file, void *opaque)
{
	struct acrd_rsp **rsp = opaque;

	*rsp = append_arg(*rsp, file, strlen(file) + 1);
	if (!*rsp)
		return ENOMEM;

	return 0;
}

static int exec_list_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			 struct acrd_txid *txid, struct client_info *from)
{
	int ret;
	const char *path = NULL;

	if (req->data_length > 0)
		path = get_arg(req, 0)->data;

	ret = store_list(path, add_file_to_list, rsp, txid);

	(*rsp)->result = ret;

	return 0;
}

static int exec_add_watch_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			      struct acrd_txid *txid, struct client_info *from)
{
	struct watcher *w = NULL;
	const char *path, *data;

	path = get_arg(req, 0)->data;
	data = get_arg(req, 1)->data;

	w = zalloc(sizeof(struct watcher));
	if (w == NULL)
		goto failed;

	w->ci = from;
	w->path = strdup(path);
	w->id = req->id;
	memcpy(&w->mask, data, sizeof(w->mask));
	dprintf("added path %s\n", w->path);

	list_add(&w->w_list, &watchers_list);

	*rsp = add_arg(*rsp, &w->id, sizeof(w->id));
	(*rsp)->result = ACRD_SUCCESS;

	return ACRD_SUCCESS;
failed:
	free(w);
	return ACRD_ERR_UNKNOWN;
}

static int exec_rm_watch_req(const struct acrd_req *req, struct acrd_rsp **rsp,
			     struct acrd_txid *txid, struct client_info *from)
{
	struct watcher *w, *wtmp;
	int ret = ACRD_ERR_NOTFOUND;
	uint32_t id;

	memcpy(&id, get_arg(req, 0)->data, sizeof(id));

	list_for_each_entry_safe(w, wtmp, &watchers_list, w_list) {
		if (w->ci == from && w->id == id) {
			free(w->path);
			list_del(&w->w_list);
			free(w);
			ret = ACRD_SUCCESS;
			break;
		}
	}

	(*rsp)->result = ret;

	return ret;
}

static int cmp_watch_path(const char *path, const char *watch_path, uint32_t ev)
{
	if (ev & ACRD_EVENT_PREFIX)
		return strncmp(path, watch_path, strlen(watch_path));
	else
		return strcmp(path, watch_path);
}

static void notify_write_event(const struct acrd_req *req)
{
	struct watcher *w;
	const char *path;

	path = get_arg(req, 0)->data;

	list_for_each_entry(w, &watchers_list, w_list) {
		if (cmp_watch_path(path, w->path, w->mask) == 0) {
			if (req->flags & ACRD_FLAG_CREATE) {
				dprintf("created\n");
				if (w->mask & ACRD_EVENT_CREATED)
					do_notify_event(req, ACRD_EVENT_CREATED,
							w->id, w->ci);
			} else {
				dprintf("changed\n");
				if (w->mask & ACRD_EVENT_CHANGED)
					do_notify_event(req, ACRD_EVENT_CHANGED,
							w->id, w->ci);
			}
		}
	}
}

static void notify_del_event(const struct acrd_req *req)
{
	struct watcher *w;
	const char *path;

	path = get_arg(req, 0)->data;

	list_for_each_entry(w, &watchers_list, w_list) {
		if (cmp_watch_path(path, w->path, w->mask) == 0) {
			dprintf("deleted\n");
			if (w->mask & ACRD_EVENT_DELETED)
				do_notify_event(req, ACRD_EVENT_DELETED, w->id,
						w->ci);
		}
	}
}

static void notify_copy_event(const struct acrd_req *req)
{
	struct watcher *w;
	const char *path;

	path = get_arg(req, 1)->data;

	list_for_each_entry(w, &watchers_list, w_list) {
		if (cmp_watch_path(path, w->path, w->mask) == 0) {
			dprintf("copied\n");
			if (w->mask & ACRD_EVENT_COPIED)
				do_notify_event(req, ACRD_EVENT_COPIED, w->id,
						w->ci);
		}
	}
}

static void notify_tx_event(const struct acrd_req *req)
{
	struct acrd_op_tmpl *op;
	const struct acrd_arg *arg;
	const struct acrd_req *child_req;

	for_each_arg(arg, req) {
		child_req = (const struct acrd_req *)arg->data;
		op = find_op(child_req->opcode);
		if (op->notify_event)
			op->notify_event(child_req);
	}
}

static struct acrd_op_tmpl acrd_ops[] = {
	{
		.opcode = ACRD_OP_WRITE,
		.need_mcast = 1,
		.exec_multi_reqs = exec_write_multi_reqs,
		.exec_req = exec_write_req,
		.notify_event = notify_write_event,
	}, {
		.opcode = ACRD_OP_READ,
		.need_mcast = 0,
		.exec_req = exec_read_req,
	}, {
		.opcode = ACRD_OP_DEL,
		.need_mcast = 1,
		.exec_req = exec_del_req,
		.notify_event = notify_del_event,
	}, {
		.opcode = ACRD_OP_CMP,
		.need_mcast = 1,
		.exec_req = exec_cmp_req,
	}, {
		.opcode = ACRD_OP_SCMP,
		.need_mcast = 1,
		.exec_req = exec_scmp_req,
	}, {
		.opcode = ACRD_OP_COPY,
		.need_mcast = 1,
		.exec_req = exec_copy_req,
		.notify_event = notify_copy_event,
	}, {
		.opcode = ACRD_OP_TX,
		.need_mcast = 1,
		.exec_req = exec_tx_req,
		.notify_event = notify_tx_event,
	}, {
		.opcode = ACRD_OP_LIST,
		.need_mcast = 0,
		.exec_req = exec_list_req,
	}, {
		.opcode = ACRD_OP_ADD_WATCH,
		.need_mcast = 0,
		.exec_req = exec_add_watch_req,
	}, {
		.opcode = ACRD_OP_RM_WATCH,
		.need_mcast = 0,
		.exec_req = exec_rm_watch_req,
	}
};

struct acrd_op_tmpl *find_op(enum OPERATION opcode)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(acrd_ops); i++) {
		if (opcode == acrd_ops[i].opcode)
			return acrd_ops + i;
	}
	eprintf("no such acrd_op, %d\n", opcode);
	abort();
}
