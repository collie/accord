/*
 * Copyright (C) 2011 OZAWA Tsuyoshi <ozawa.tsuyoshi@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <assert.h>

#include "list.h"
#include "accord.h"
#include "util.h"
#include "net.h"
#include "event.h"
#include "work.h"
#include "coroutine.h"

#define dprintf(fmt, args...)						\
do {									\
	fprintf(stdout, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define eprintf(fmt, args...)						\
do {									\
	fprintf(stderr, "%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define MAX_EVENT_SIZE 4096
#define MAX_REQESUTS 100000
#define MAX_ALLOC_SIZE (64 * 1024 * 1024)
#define INTERVAL 1 /* ms */

/* FIXME: make these values configurable */
#define KEEPIDLE    20
#define KEEPINTVL   20
#define KEEPCNT     2

struct request;

typedef void (*acrd_recv_cb_t)(struct acrd_handle *h, struct acrd_rsp *rsp,
			      void *opaque);
struct request {
	struct acrd_handle *handle;

	struct acrd_req *rq;
	struct acrd_aiocb *aiocb;

	acrd_recv_cb_t recv_cb;
	void *arg;

	/* work list */
	struct list_head w_list;

	struct list_head siblings;
};

struct acrd_handle {
	int fd;
	uint32_t msgid;

	acrd_confchg_cb_t join_fn;
	acrd_confchg_cb_t leave_fn;
	void *ctx;
	struct work_queue *send_queue;

	pthread_mutex_t sync_lock;
	pthread_cond_t sync_cond;

	pthread_t recv_thread;
	struct co_buffer recv_buf;

	uint32_t seq_no;

	struct list_head nosync_reqs;
	struct list_head sync_reqs;
	int nr_outstanding_reqs;
	uint64_t allocated_data_size;

	struct list_head watch_list;
};

struct acrd_read_info {
	uint32_t *size;
	void *buf;
};

struct acrd_tx {
	struct acrd_handle   *handle;
	struct request      *req;

	size_t nr_read_info;
	struct acrd_read_info *read_info;
};

struct acrd_watch {
	struct acrd_watch_info info;

	struct list_head list;
};

static void set_request_info(struct acrd_req *req, int opcode, uint32_t flags)
{
	req->type = ACRD_MSG_REQUEST;
	req->opcode = opcode;
	req->flags = flags;
}

static struct request *req_new(struct acrd_handle *ah, enum OPERATION op,
			       uint32_t flags, acrd_recv_cb_t recv_cb, void *arg)
{
	struct request *req;

	req = zalloc(sizeof(*req));
	if (unlikely(req == NULL))
		goto oom;

	req->rq = zalloc(sizeof(*req->rq));
	if (unlikely(req->rq == NULL))
		goto oom;

	set_request_info(req->rq, op, flags);

	req->handle = ah;
	req->recv_cb = recv_cb;
	req->arg = arg;

	return req;
oom:
	free(req);
	eprintf("oom\n");
	return NULL;
}

static void acrd_send(struct list_head *work_list)
{
	int fd = 0;
	struct request *req;
	struct iovec iov[UIO_MAXIOV];
	int cnt, len, offset, ret;
	fd_set wfds;
again:
	len = 0;
	for (cnt = 0; !list_empty(work_list) && cnt < ARRAY_SIZE(iov); cnt++) {
		req = list_first_entry(work_list, struct request, w_list);
		list_del(&req->w_list);

		req->rq->id = req->handle->seq_no++;

		pthread_mutex_lock(&req->handle->sync_lock);
		if (req->rq->flags & ACRD_FLAG_SYNC)
			list_add_tail(&req->siblings, &req->handle->sync_reqs);
		else
			list_add_tail(&req->siblings, &req->handle->nosync_reqs);
		pthread_mutex_unlock(&req->handle->sync_lock);

		fd = req->handle->fd;

		len += sizeof(*req->rq) + req->rq->data_length;

		iov[cnt].iov_base = req->rq;
		iov[cnt].iov_len = sizeof(*req->rq) + req->rq->data_length;
	}

	offset = 0;
	while (len) {
		set_cork(fd);
		ret = do_writev(fd, iov, len, offset);
		unset_cork(fd);

		if (ret < 0) {
			if (errno != EAGAIN) {
				dprintf("exit send thread\n");
				return;
			}

			FD_ZERO(&wfds);
			FD_SET(fd, &wfds);

			ret = select(fd + 1, NULL, &wfds, NULL, NULL);
			if (ret < 0) {
				eprintf("select\n");
				return;
			}
			continue;
		}

		offset += ret;
		len -= ret;
	}

	if (!list_empty(work_list))
		goto again;
}

static struct request *find_req(struct list_head *outstanding_reqs, uint32_t id)
{
	struct request *req;

	if (list_empty(outstanding_reqs))
		return NULL;

	req = list_first_entry(outstanding_reqs, struct request, siblings);
	if (unlikely(req->rq->id != id))
		return NULL;

	return req;
}

static int acrd_aio_completion(struct acrd_handle *ah, struct acrd_rsp *rsp)
{
	int ret = 0;
	struct request *req;
	struct acrd_aiocb *acb;

	req = find_req(&ah->nosync_reqs, rsp->id);
	if (!req)
		req = find_req(&ah->sync_reqs, rsp->id);

	if (unlikely(!req)) {
		eprintf("internal error\n");
		abort();
	}

	if (req->recv_cb)
		req->recv_cb(ah, rsp, req->arg);

	acb = req->aiocb;
	acb->result = rsp->result;
	if (acb->cb)
		acb->cb(ah, acb, acb->arg);

	pthread_mutex_lock(&ah->sync_lock);
	acb->done = 1;
	__sync_sub_and_fetch(&ah->nr_outstanding_reqs, 1);
	list_del(&req->siblings);
	pthread_mutex_unlock(&ah->sync_lock);

	pthread_cond_broadcast(&ah->sync_cond);

	__sync_sub_and_fetch(&ah->allocated_data_size, req->rq->data_length);

	free(req->rq);
	free(req);

	return ret;
}

static int acrd_ntfy_completion(struct acrd_handle *ah, struct acrd_ntfy *ntfy)
{
	struct acrd_watch *w;
	struct acrd_watch_info *wi;
	const struct acrd_arg *id_arg, *list_arg;
	const struct acrd_arg *path_arg, *data_arg;
	uint64_t nodeid = 0;
	int nr_ids = 0;

	path_arg = id_arg = get_arg(ntfy, 0);
	data_arg = list_arg = get_arg(ntfy, 1);

	if (ntfy->events & ACRD_EVENT_CONFCHG_MASK) {
		assert(ntfy->nr_args == 2);
		assert(id_arg->size == sizeof(uint64_t));
		assert(list_arg->size % sizeof(uint64_t) == 0);

		memcpy(&nodeid, id_arg->data, sizeof(nodeid));
		nr_ids = list_arg->size / sizeof(uint64_t);
	}

	switch (ntfy->events) {
	case ACRD_EVENT_JOINED:
		if (ah->join_fn)
			ah->join_fn(ah, (uint64_t *)list_arg->data, nr_ids,
				    nodeid, ah->ctx);
		break;
	case ACRD_EVENT_LEFT:
		if (ah->leave_fn)
			ah->leave_fn(ah, (uint64_t *)list_arg->data, nr_ids,
				     nodeid, ah->ctx);
		break;
	default:
		list_for_each_entry(w, &ah->watch_list, list) {
			wi = &w->info;
			if (wi->id == ntfy->id)  {
				wi->path = path_arg->data;
				wi->events = ntfy->events;
				wi->offset = ntfy->offset;
				if (data_arg) {
					wi->data = data_arg->data;
					wi->data_len = data_arg->size;
				} else {
					wi->data = NULL;
					wi->data_len = 0;
				}

				wi->cb(wi->handle, wi, wi->ctx);

				break;
			}
		}
		break;
	}

	return 0;
}

static void __acrd_recv(void *opaque)
{
	struct acrd_handle *ah = opaque;
	struct acrd_common_hdr hdr, *msg;
	int ret;
again:
	do_co_read(&ah->recv_buf, &hdr, sizeof(hdr));

	msg = zalloc(sizeof(hdr) + hdr.data_length);
	memcpy(msg, &hdr, sizeof(hdr));

	do_co_read(&ah->recv_buf, msg->data, msg->data_length);

	switch (msg->type) {
	case ACRD_MSG_RESPONSE:
		ret = acrd_aio_completion(ah, (struct acrd_rsp *)msg);
		if (unlikely(ret != 0))
			eprintf("error\n");
		break;
	case ACRD_MSG_NOTIFICATION:
		ret = acrd_ntfy_completion(ah, (struct acrd_ntfy *)msg);
		if (unlikely(ret != 0))
			eprintf("error\n");
		break;
	default:
		eprintf("invalide msg type, %d\n", msg->type);
		break;
	}

	free(msg);

	goto again;
}

static void *acrd_recv(void *arg)
{
	struct acrd_handle *ah = arg;
	int fd = ah->fd;
	int ret;
	struct coroutine *co;
	char buf[1024 * 1024];
	fd_set rfds;

	co = coroutine_create(__acrd_recv);

	for (;;) {
		ret = do_read(fd, buf, sizeof(buf));
		if (ret < 0) {
			dprintf("exit recv thread\n");
			break;
		}

		if (ret == 0) {
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);

			ret = select(fd + 1, &rfds, NULL, NULL, NULL);
			if (ret < 0) {
				eprintf("select\n");
				break;
			}
			continue;
		}

		ah->recv_buf.offset = 0;
		ah->recv_buf.len = ret;
		ah->recv_buf.buf = buf;

		coroutine_enter(co, ah);
	}

	pthread_exit(NULL);
}

struct acrd_handle *acrd_init(const char *hostname, int port,
			    acrd_confchg_cb_t join_cb, acrd_confchg_cb_t leave_cb,
			    void *ctx)
{
	int fd, ret;
	struct acrd_handle *handle;

	handle = zalloc(sizeof(struct acrd_handle));
	if (handle == NULL) {
		eprintf("failed to allocate handler.\n");
		return NULL;
	}

	pthread_mutex_init(&handle->sync_lock, NULL);
	pthread_cond_init(&handle->sync_cond, NULL);

	INIT_LIST_HEAD(&handle->nosync_reqs);
	INIT_LIST_HEAD(&handle->sync_reqs);
	INIT_LIST_HEAD(&handle->watch_list);

	fd = connect_to(hostname,  port, KEEPIDLE, KEEPINTVL, KEEPCNT);
	if (fd < 0) {
		eprintf("failed to connect.\n");
		free(handle);
		return NULL;
	}

	ret = set_nonblocking(fd);
	if (ret < 0) {
		eprintf("failed to set noblocking.\n");
		close(fd);
		free(handle);
		return NULL;
	}

	ret = set_nodelay(fd);
	if (ret) {
		eprintf("failed to set nodelay.\n");
		close(fd);
		free(handle);
		return NULL;
	}

	handle->fd = fd;

	handle->send_queue = init_work_queue(acrd_send, INTERVAL);

	ret = pthread_create(&handle->recv_thread, NULL, acrd_recv, handle);
	if (ret < 0) {
		eprintf("failed to init thread.\n");
		exit(1);
	}

	handle->join_fn = join_cb;
	handle->leave_fn = leave_cb;
	handle->ctx = ctx;

	return handle;
}

int acrd_close(struct acrd_handle *ah)
{
	int ret = 0;

	acrd_aio_flush(ah);

	pthread_cancel(ah->recv_thread);
	pthread_join(ah->recv_thread, NULL);

	exit_work_queue(ah->send_queue);

	ret = close(ah->fd);
	free(ah);

	return ret;
}

static void acrd_tx_cb(struct acrd_handle *h, struct acrd_rsp *rsp,
		      void *opaque)
{
	struct acrd_tx *tx = opaque;
	const struct acrd_arg *arg;
	int i = 0;

	assert(rsp->nr_args == 0 || rsp->nr_args == tx->nr_read_info);
	for_each_arg(arg, rsp) {
		*tx->read_info[i].size = arg->size;
		memcpy(tx->read_info[i].buf, arg->data, arg->size);
		i++;
	}
}

struct acrd_tx *acrd_tx_init(struct acrd_handle *ah)
{
	struct acrd_tx *tx;

	tx = zalloc(sizeof(*tx));
	if (!tx)
		return NULL;

	tx->handle = ah;
	tx->req = req_new(ah, ACRD_OP_TX, 0, acrd_tx_cb, tx);

	return tx;
}

void acrd_tx_close(struct acrd_tx * tx)
{
	free(tx->read_info);
	free(tx);
}

static int acrd_op(struct acrd_handle *ah, struct acrd_tx *tx, enum OPERATION op,
		  const void *data1, size_t data1_len, const void *data2,
		  size_t data2_len, uint32_t size, uint64_t offset, uint32_t flags,
		  acrd_recv_cb_t recv_cb, void *arg, struct acrd_aiocb *aiocb)
{
	struct request *req;
	int need_sync = !aiocb;
	int ret = ACRD_SUCCESS;

	if (ah->nr_outstanding_reqs > MAX_REQESUTS)
		return ACRD_ERR_AGAIN;

	if (ah->allocated_data_size > MAX_ALLOC_SIZE)
		return ACRD_ERR_AGAIN;

	req = req_new(ah, op, flags, recv_cb, arg);
	if (req == NULL) {
		eprintf("oom\n");
		return ACRD_ERR_AGAIN;
	}

	req->rq->size = size;
	req->rq->offset = offset;

	if (data1)
		req->rq = add_arg(req->rq, data1, data1_len);
	if (data2)
		req->rq = add_arg(req->rq, data2, data2_len);

	if (tx) {
		tx->req->rq = add_arg(tx->req->rq, req->rq,
				      sizeof(*req->rq) + req->rq->data_length);
		free(req->rq);
		free(req);
	} else {
		if (need_sync)
			aiocb = acrd_aio_setup(ah, NULL, NULL);

		__sync_add_and_fetch(&ah->nr_outstanding_reqs, 1);
		__sync_add_and_fetch(&ah->allocated_data_size, req->rq->data_length);
		req->aiocb = aiocb;
		queue_work(ah->send_queue, &req->w_list);

		if (need_sync) {
			acrd_aio_wait(ah, aiocb);
			ret = aiocb->result;
			acrd_aio_release(ah, aiocb);
		}
	}

	return ret;
}

int acrd_tx_write(struct acrd_tx *tx, const char *path, const void *buf,
	       uint32_t count, uint64_t offset, uint32_t flags)
{
	return acrd_op(tx->handle, tx, ACRD_OP_WRITE, path, strlen(path) + 1, buf,
		      count, count, offset, flags, NULL, NULL, NULL);
}

int acrd_tx_read(struct acrd_tx *tx, const char *path, void *buf, uint32_t *count,
		uint64_t offset, uint32_t flags)
{
	tx->nr_read_info++;
	tx->read_info = realloc(tx->read_info,
				sizeof(*tx->read_info) * tx->nr_read_info);
	tx->read_info[tx->nr_read_info - 1].buf = buf;
	tx->read_info[tx->nr_read_info - 1].size = count;

	return acrd_op(tx->handle, tx, ACRD_OP_READ, path, strlen(path) + 1, NULL,
		      0, *count, offset, flags, NULL, NULL, NULL);
}

int acrd_tx_del(struct acrd_tx *tx, const char *path, uint32_t flags)
{
	return acrd_op(tx->handle, tx, ACRD_OP_DEL, path, strlen(path) + 1, NULL,
		      0, 0, 0, flags, NULL, NULL, NULL);
}

int acrd_tx_cmp(struct acrd_tx *tx, const char *path, const void *buf,
	       uint32_t count, uint32_t flags)
{
	return acrd_op(tx->handle, tx, ACRD_OP_CMP, path, strlen(path) + 1, buf,
		      count, 0, 0, flags, NULL, NULL, NULL);
}

int acrd_tx_scmp(struct acrd_tx *tx, const char *p1, const char *p2,
		uint32_t flags)
{
	return acrd_op(tx->handle, tx, ACRD_OP_SCMP, p1, strlen(p1) + 1, p2,
		      strlen(p2) + 1, 0, 0, flags, NULL, NULL, NULL);
}

int acrd_tx_copy(struct acrd_tx *tx, const char *src, const char *dst,
		uint32_t flags)
{
	return acrd_op(tx->handle, tx, ACRD_OP_COPY, src, strlen(src) + 1, dst,
		      strlen(dst) + 1, 0, 0, flags, NULL, NULL, NULL);
}

int acrd_tx_commit(struct acrd_tx *tx, uint32_t flags)
{
	struct acrd_aiocb *aiocb;
	int ret;
	struct acrd_handle *ah = tx->handle;

	aiocb = acrd_aio_setup(ah, NULL, NULL);

	ret = acrd_tx_aio_commit(tx, flags, aiocb);

	acrd_aio_wait(ah, aiocb);
	ret = aiocb->result;
	acrd_aio_release(ah, aiocb);

	return ret;
}

/* TODO: we should merge this function with acrd_op() */
int acrd_tx_aio_commit(struct acrd_tx *tx, uint32_t flags, struct acrd_aiocb *aiocb)
{
	int ret = 0;
	struct acrd_handle *ah = tx->handle;

	set_request_info(tx->req->rq, ACRD_OP_TX, flags);

	__sync_add_and_fetch(&ah->nr_outstanding_reqs, 1);
	__sync_add_and_fetch(&ah->allocated_data_size, tx->req->rq->data_length);
	tx->req->aiocb = aiocb;
	queue_work(ah->send_queue, &tx->req->w_list);

	return ret;
}

int acrd_write(struct acrd_handle *ah, const char *path, const void *data,
	      uint32_t count, uint64_t offset, uint32_t flags)
{
	return acrd_op(ah, NULL, ACRD_OP_WRITE, path, strlen(path) + 1, data, count,
		      count, offset, flags, NULL, NULL, NULL);
}

static void acrd_read_cb(struct acrd_handle *h, struct acrd_rsp *rsp,
			void *opaque)
{
	struct acrd_read_info *info = opaque;
	const struct acrd_arg *arg;

	arg = get_arg(rsp, 0);
	if (arg) {
		*info->size = arg->size;
		memcpy(info->buf, arg->data, arg->size);
	}

	free(info);
}

int acrd_read(struct acrd_handle *ah, const char *path, void *data,
	     uint32_t *count, uint64_t offset, uint32_t flags)
{
	struct acrd_read_info *info;

	info = malloc(sizeof(*info));
	info->size = count;
	info->buf = data;

	return acrd_op(ah, NULL, ACRD_OP_READ, path, strlen(path) + 1, NULL, 0,
		      *count, offset, flags, acrd_read_cb, info, NULL);
}

int acrd_del(struct acrd_handle *ah, const char *path, uint32_t flags)
{
	return acrd_op(ah, NULL, ACRD_OP_DEL, path, strlen(path) + 1, NULL, 0,
		      0, 0, flags, NULL, NULL, NULL);
}

int acrd_copy(struct acrd_handle *ah, const char *src, const char *dst,
	     uint32_t flags)
{
	return acrd_op(ah, NULL, ACRD_OP_COPY, src, strlen(src) + 1, dst,
		      strlen(dst) + 1, 0, 0, flags, NULL, NULL, NULL);
}

static void acrd_list_cb(struct acrd_handle *h, struct acrd_rsp *rsp,
			void *opaque)
{
	struct acrd_listcb *listcb = opaque;
	const struct acrd_arg *arg;
	const char *path;

	if (!listcb->cb)
		return;

	arg = get_arg(rsp, 0);
	if (!arg)
		return;

	path = arg->data;
	while (path - (char *)arg->data < arg->size) {
		listcb->cb(h, path, listcb->arg);
		path += strlen(path) + 1;
	}
}

int acrd_list(struct acrd_handle *ah, const char *prefix, uint32_t flags,
	     struct acrd_listcb *listcb)
{
	int len = 0;

	if (prefix)
		len = strlen(prefix) + 1;

	return acrd_op(ah, NULL, ACRD_OP_LIST, prefix, len, NULL, 0, 0, 0, flags,
		      acrd_list_cb, listcb, NULL);
}

struct acrd_aiocb *acrd_aio_setup(struct acrd_handle *h, acrd_aio_cb_t cb,
				void *arg)
{
	struct acrd_aiocb *aiocb;

	aiocb = zalloc(sizeof(*aiocb));
	if (unlikely(!aiocb)) {
		eprintf("oom\n");
		return NULL;
	}

	aiocb->handle = h;
	aiocb->cb = cb;
	aiocb->arg = arg;

	return aiocb;
}

void acrd_aio_release(struct acrd_handle *h, struct acrd_aiocb *aiocb)
{
	free(aiocb);
}

void acrd_aio_wait(struct acrd_handle *h, struct acrd_aiocb *aiocb)
{
	pthread_mutex_lock(&h->sync_lock);

	while (!aiocb->done)
		pthread_cond_wait(&h->sync_cond, &h->sync_lock);

	pthread_mutex_unlock(&h->sync_lock);
}

void acrd_aio_flush(struct acrd_handle *h)
{
	pthread_mutex_lock(&h->sync_lock);

	while (h->nr_outstanding_reqs > 0)
		pthread_cond_wait(&h->sync_cond, &h->sync_lock);

	pthread_mutex_unlock(&h->sync_lock);
}

int acrd_aio_write(struct acrd_handle *ah, const char *path, const void *data,
		  uint32_t count, uint64_t offset, uint32_t flags,
		  struct acrd_aiocb *aiocb)
{
	return acrd_op(ah, NULL, ACRD_OP_WRITE, path, strlen(path) + 1, data, count,
		      count, offset, flags, NULL, NULL, aiocb);
}

int acrd_aio_read(struct acrd_handle *ah, const char *path, void *data,
		 uint32_t *count, uint64_t offset, uint32_t flags,
		 struct acrd_aiocb *aiocb)
{
	struct acrd_read_info *info;

	info = malloc(sizeof(*info));
	info->size = count;
	info->buf = data;

	return acrd_op(ah, NULL, ACRD_OP_READ, path, strlen(path) + 1, NULL, 0,
		      *count, offset, flags, acrd_read_cb, info, aiocb);
}

int acrd_aio_del(struct acrd_handle *ah, const char *path, uint32_t flags,
		struct acrd_aiocb *aiocb)
{
	return acrd_op(ah, NULL, ACRD_OP_DEL, path, strlen(path) + 1, NULL, 0,
		      0, 0, flags, NULL, NULL, aiocb);
}

int acrd_aio_copy(struct acrd_handle *ah, const char *src, const char *dst,
		 uint32_t flags, struct acrd_aiocb *aiocb)
{
	return acrd_op(ah, NULL, ACRD_OP_COPY, src, strlen(src) + 1, dst,
		      strlen(dst) + 1, 0, 0, flags, NULL, NULL, aiocb);
}

int acrd_aio_list(struct acrd_handle *ah, const char *prefix, uint32_t flags,
		 struct acrd_listcb *listcb, struct acrd_aiocb *aiocb)
{
	int len = 0;

	if (prefix)
		len = strlen(prefix) + 1;

	return acrd_op(ah, NULL, ACRD_OP_LIST, prefix, len, NULL, 0, 0, 0, flags,
		      acrd_list_cb, listcb, aiocb);
}

static void acrd_add_watch_cb(struct acrd_handle *h, struct acrd_rsp *rsp,
			     void *opaque)
{
	struct acrd_watch_info *info = opaque;
	const struct acrd_arg *arg;

	arg = get_arg(rsp, 0);
	if (arg) {
		assert(sizeof(info->id) == arg->size);
		memcpy(&info->id, arg->data, arg->size);
	}
}

struct acrd_watch_info *acrd_add_watch(struct acrd_handle *h, const char *path,
				     uint32_t mask, acrd_watch_cb_t cb, void *arg)
{
	int ret;
	struct acrd_watch *w;
	struct acrd_watch_info *wi;

	w = zalloc(sizeof(*w));
	if (unlikely(!w)) {
		eprintf("oom\n");
		return NULL;
	}
	wi = &w->info;
	wi->handle = h;
	wi->cb = cb;
	wi->mask = mask;
	wi->ctx = arg;

	ret = acrd_op(h, NULL, ACRD_OP_ADD_WATCH, path, strlen(path) + 1,
		     &mask, sizeof(mask), 0, 0, 0, acrd_add_watch_cb, wi, NULL);
	if (ret != ACRD_SUCCESS) {
		free(wi);
		return NULL;
	}
	list_add(&w->list, &h->watch_list);

	return wi;
}

int acrd_rm_watch(struct acrd_handle *h, struct acrd_watch_info *wi)
{
	struct acrd_watch *w = container_of(wi, struct acrd_watch, info);
	int ret;

	ret = acrd_op(h, NULL, ACRD_OP_RM_WATCH, &wi->id, sizeof(wi->id),
		     NULL, 0, 0, 0, 0, NULL, NULL, NULL);
	if (ret == ACRD_SUCCESS)
		list_del(&w->list);

	return ret;
}
