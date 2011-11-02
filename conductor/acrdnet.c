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
#include <stdlib.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <corosync/cpg.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#include "accord_proto.h"
#include "list.h"
#include "work.h"
#include "logger.h"
#include "util.h"
#include "net.h"
#include "event.h"
#include "acrd_priv.h"
#include "store.h"
#include "coroutine.h"

struct client_id {
	union {
		struct {
			uint32_t nodeid;
			uint32_t seq_no;
		};
		uint64_t id;
	};
	struct list_head id_list;
};

enum client_status {
	CLIENT_STATUS_CONNECTED,
	CLIENT_STATUS_JOINED,
	CLIENT_STATUS_DEAD,
};

struct client_info {
	struct client_id cid;
	struct list_head siblings;

	int fd;
	enum client_status status;
	unsigned int events;
	int nr_outstanding_reqs;
	uint64_t rx_len;
	uint64_t tx_len;
	struct co_buffer rx_buf;

	struct coroutine *rx_co;
	struct coroutine *tx_co;
	struct list_head rx_list;
	struct list_head tx_list;
	int tx_on; /* if true, send_response() is sending response through
		    * this connection */
	pthread_mutex_t tx_lock; /* protect tx_on and rsp_list */

	struct list_head rsp_list;

	int tx_failed;
	int stop; /* if true, the connection is not ready for read
		   * operations because of too many requests */

	int refcnt;

};

struct cpg_request {
	struct acrd_common_hdr *msg;

	struct list_head w_list;
};

struct bs_request {
	/* mcasted msg */
	struct acrd_req *rq;

	/* if rsp is non-NULL, this request is from localhost. */
	struct response *rsp;

	struct list_head w_list;
};

struct response {
	struct acrd_req *rq;
	struct acrd_common_hdr *msg;

	struct client_info *ci;

	struct list_head siblings;

	struct list_head w_list;
};

/**
 * notification message format
 * hdr  : acrd_msg
 * path : size(uint32_t) | path_body
 * data : size(uint32_t) | data_body
 */

/* can be accessed only in main thread */
static LIST_HEAD(client_info_list);
static LIST_HEAD(client_id_list);

static pthread_mutex_t outstanding_reqs_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(outstanding_reqs);

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;

static cpg_handle_t cpg_handle;
static uint32_t local_nodeid;

static struct work_queue *recv_queue[NR_RECV_THREAD];
static struct work_queue *send_queue[NR_SEND_THREAD];
static struct work_queue *bs_queue;
static struct work_queue *cpg_queue;
static struct work_queue *sync_queue;

extern int keepidle, keepintvl, keepcnt;

static void destroy_client(struct client_info *ci)
{
	close(ci->fd);
	free(ci);
}

static void client_incref(struct client_info *ci)
{
	if (ci)
		__sync_add_and_fetch(&ci->refcnt, 1);
}

static void client_decref(struct client_info *ci)
{
	if (ci && __sync_sub_and_fetch(&ci->refcnt, 1) == 0) {
		destroy_client(ci);
		return;
	}
}

static int too_many_requests(struct client_info *ci)
{
	return ci->nr_outstanding_reqs > 10000 || ci->rx_len > 4 * 1048576 ||
		ci->tx_len > 4 * 1048576;
}

static void client_rx_on(struct client_info *ci)
{
	pthread_mutex_lock(&event_lock);
	ci->events |= EPOLLIN;
	modify_event(ci->fd, ci->events);
	pthread_mutex_unlock(&event_lock);
}

static void client_rx_off(struct client_info *ci)
{
	pthread_mutex_lock(&event_lock);
	ci->events &= ~EPOLLIN;
	modify_event(ci->fd, ci->events);
	pthread_mutex_unlock(&event_lock);
}

static void client_tx_on(struct client_info *ci)
{
	pthread_mutex_lock(&event_lock);
	ci->events |= EPOLLOUT;
	modify_event(ci->fd, ci->events);
	pthread_mutex_unlock(&event_lock);
}

static void client_tx_off(struct client_info *ci)
{
	pthread_mutex_lock(&event_lock);
	ci->events &= ~EPOLLOUT;
	modify_event(ci->fd, ci->events);
	pthread_mutex_unlock(&event_lock);
}


static struct response *alloc_response(struct client_info *ci,
				       struct acrd_common_hdr *msg)
{
	struct response *rsp;

	client_incref(ci);
	__sync_add_and_fetch(&ci->nr_outstanding_reqs, 1);

	rsp = zalloc(sizeof(*rsp));
	rsp->ci = ci;
	rsp->msg = msg;

	return rsp;
}

static void free_response(struct response *rsp)
{
	struct client_info *ci = rsp->ci;

	client_decref(ci);
	__sync_sub_and_fetch(&ci->nr_outstanding_reqs, 1);

	free(rsp->msg);
	free(rsp);
}

static void queue_response(struct response *rsp)
{
	struct client_info *ci = rsp->ci;

	if (ci->status == CLIENT_STATUS_DEAD) {
		free_response(rsp);
		return;
	}

	pthread_mutex_lock(&ci->tx_lock);
	list_add_tail(&rsp->w_list, &ci->rsp_list);
	if (ci->tx_on == 0)
		client_tx_on(ci);
	pthread_mutex_unlock(&ci->tx_lock);
}

static void bs_sync(struct list_head *work_list)
{
	struct bs_request *bsreq;

	store_sync();

	while (!list_empty(work_list)) {
		bsreq = list_first_entry(work_list, struct bs_request, w_list);
		list_del(&bsreq->w_list);

		queue_response(bsreq->rsp);

		free(bsreq);
	}
}

static void exec_multi_reqs(struct list_head *req_list, int *ret)
{
	int nr = 0;
	struct bs_request *bsreq;
	const struct acrd_req *reqs[MAX_MULTI_REQS];
	struct acrd_rsp **rsps[MAX_MULTI_REQS];
	struct acrd_op_tmpl *op;

	bsreq = list_first_entry(req_list, struct bs_request, w_list);
	op = find_op(bsreq->rq->opcode);

	list_for_each_entry(bsreq, req_list, w_list) {
		reqs[nr] = bsreq->rq;
		if (bsreq->rsp)
			rsps[nr] = (struct acrd_rsp **)&bsreq->rsp->msg;
		else
			rsps[nr] = NULL;
		nr++;
	}

	op->exec_multi_reqs(reqs, rsps, ret - nr, nr, NULL);
}

static void bs_exec_request(struct list_head *work_list)
{
	struct bs_request *bsreq = NULL;
	int ret[MAX_MULTI_REQS], i, nr_reqs;
	struct response *rsp;
	struct acrd_req *req;
	struct acrd_op_tmpl *op;
	uint8_t prev_opcode = 0;
	LIST_HEAD(done_list);
	LIST_HEAD(req_list);
again:
	INIT_LIST_HEAD(&req_list);
	for (i = 0; i < MAX_MULTI_REQS; i++, prev_opcode = req->opcode) {
		if (list_empty(work_list))
			break;

		bsreq = list_first_entry(work_list, struct bs_request, w_list);
		list_del(&bsreq->w_list);

		rsp = bsreq->rsp;
		req = bsreq->rq;
		op = find_op(req->opcode);

		if (!list_empty(&req_list)) {
			if (prev_opcode == req->opcode) {
				/* link bsreq to req_list for exec_multi_reqs() */
				list_add_tail(&bsreq->w_list, &req_list);
				continue;
			}
			/* do exec_multi_reqs() */
			exec_multi_reqs(&req_list, ret + i);

			list_splice_tail_init(&req_list, &done_list);
		}

		if (op->exec_multi_reqs)
			/* link bsreq to req_list for exec_multi_reqs() */
			list_add_tail(&bsreq->w_list, &req_list);
		else {
			/* do exec_req() */
			if (rsp) {
				ret[i] = op->exec_req(req, (struct acrd_rsp **)&rsp->msg, NULL, rsp->ci);
				dprintf("ret : %d result %d\n", ret[i], ((struct acrd_rsp *)rsp->msg)->result);
			} else {
				ret[i] = op->exec_req(req, NULL, NULL, NULL);
				dprintf("ret : %d\n", ret[i]);
			}

			list_add_tail(&bsreq->w_list, &done_list);
		}
	}
	nr_reqs = i;

	if (!list_empty(&req_list)) {
		exec_multi_reqs(&req_list, ret + nr_reqs);

		list_splice_tail_init(&req_list, &done_list);
	}

	for (i = 0; i < nr_reqs; i++) {
		bsreq = list_first_entry(&done_list, struct bs_request, w_list);
		list_del(&bsreq->w_list);

		rsp = bsreq->rsp;
		req = bsreq->rq;

		op = find_op(req->opcode);
		if (ret[i] == ACRD_SUCCESS && op->notify_event)
			op->notify_event(req);

		if (!rsp) {
			/* this request is not from localhost */
			free(bsreq);
			continue;
		}

		if (sync_queue && req->flags & ACRD_FLAG_SYNC)
			queue_work(sync_queue, &bsreq->w_list);
		else {
			queue_response(bsreq->rsp);

			free(bsreq);
		}
	}
	if (!list_empty(work_list))
		goto again;
}

static void notify_node_event(uint64_t nodeid, uint32_t ev)
{
	struct cpg_request *req;
	struct acrd_ntfy *ntfy;

	req = zalloc(sizeof(*req));
	if (req == NULL)
		return;

	ntfy = zalloc(sizeof(*ntfy));
	ntfy->type = ACRD_MSG_NOTIFICATION;
	ntfy->events = ev;

	ntfy = add_arg(ntfy, &nodeid, sizeof(nodeid));

	req->msg = (struct acrd_common_hdr *)ntfy;

	queue_work(cpg_queue, &req->w_list);
}

void cpg_handler(int fd, int events, void *arg)
{
	int ret;

	if (events & EPOLLHUP) {
		eprintf("Receive EPOLLHUP event. Is corosync stopped running?\n");
		exit(1);
	}

	ret = cpg_dispatch(cpg_handle, CS_DISPATCH_ALL);
	if (ret != CS_OK) {
		eprintf("unrecoverable error, %d %d\n", ret, events);
		exit(1);
	}
}

static void cpg_confchg(
		cpg_handle_t handle, const struct cpg_name *group,
		const struct cpg_address *member_list,
		size_t member_list_entries,
		const struct cpg_address *left_list, size_t left_list_entries,
		const struct cpg_address *joined_list,
		size_t joined_list_entries)
{
	int i;
	uint32_t nodeid;
	struct client_id *cid;
	/**
	CPG_REASON_JOIN     - the process joined a group using cpg_join().
	CPG_REASON_LEAVE    - the process left a group using cpg_leave()
	CPG_REASON_NODEDOWN - the process left a group because the node left the
	cluster.
	CPG_REASON_NODEUP   - the process joined a group because it was already a
	member of a group on a node that has just joined the cluster
	CPG_REASON_PROCDOWN - the process left a group without calling cpg_leave()
	*/

	dprintf("confchg nodeid %x\n", member_list[0].nodeid);
	dprintf("%zd %zd %zd\n", member_list_entries,
			left_list_entries,
			joined_list_entries);

	for (i = 0; i < member_list_entries; i++) {
		dprintf("[%d] node_id: %d,"
				"pid: %d, reason: %d\n", i,
				member_list[i].nodeid,
				member_list[i].pid,
				member_list[i].reason);
	}

	for (i = 0; i < left_list_entries; i++) {
		nodeid = left_list[i].nodeid;

		list_for_each_entry(cid, &client_id_list, id_list) {
			dprintf("nodeid: %d, cid->nodeid %d\n",
				nodeid, cid->nodeid);
			if (nodeid == cid->nodeid)
				notify_node_event(cid->id, ACRD_EVENT_LEFT);
		}
	}
}

/* set current members to one object array */
static void *add_current_members(struct acrd_ntfy *ntfy)
{
	struct client_id *cid;
	uint64_t *members = NULL;
	int cnt = 0;
	int i = 0;

	list_for_each_entry(cid, &client_id_list, id_list)
		cnt++;

	members = zalloc(cnt * sizeof(*members));
	list_for_each_entry(cid, &client_id_list, id_list) {
		memcpy(members + i, &cid->id, sizeof(uint64_t));
		i++;
	}
	ntfy = add_arg(ntfy, members, cnt * sizeof(*members));
	free(members);

	return ntfy;
}

static void update_clients_info(const void *p)
{
	struct acrd_ntfy *ntfy = (struct acrd_ntfy *)p;
	struct client_id *cid, *tmpcid;
	const struct acrd_arg *arg;
	struct client_info *ci;
	uint64_t id;

	if (!(ntfy->events & ACRD_EVENT_CONFCHG_MASK))
		return;

	arg = get_arg(ntfy, 0);
	if (arg->size != sizeof(uint64_t)) {
		eprintf("internal error\n");
		return;
	}
	memcpy(&id, arg->data, sizeof(id));

	switch (ntfy->events) {
	case ACRD_EVENT_JOINED:
		cid = zalloc(sizeof(*cid));
		cid->id = id;
		INIT_LIST_HEAD(&cid->id_list);
		list_add_tail(&cid->id_list, &client_id_list);

		list_for_each_entry(ci, &client_info_list, siblings) {
			if (ci->cid.id == id)
				ci->status = CLIENT_STATUS_JOINED;
		}

		break;
	case ACRD_EVENT_LEFT:
		list_for_each_entry_safe(cid, tmpcid, &client_id_list, id_list) {
			if (cid->id == id) {
				list_del(&cid->id_list);
				free(cid);
			}
		}
		break;
	}
}

static void queue_notify(struct client_info *ci, struct acrd_ntfy *ntfy)
{
	struct response *rsp;

	/* check whether the client is still alive or not */
	if (ci->status != CLIENT_STATUS_JOINED) {
		dprintf("client seems to be dead\n");
		return;
	}

	rsp = alloc_response(ci, (struct acrd_common_hdr *)ntfy);

	queue_response(rsp);
}

void do_notify_event(const struct acrd_req *req, uint16_t events,
		     uint32_t watch_id, struct client_info *ci)
{
	struct acrd_ntfy *ntfy = NULL;

	ntfy = zalloc(sizeof(*req) + req->data_length);
	memcpy(ntfy, req, sizeof(*req) + req->data_length);

	/* set header */
	ntfy->events = events;
	ntfy->type = ACRD_MSG_NOTIFICATION;
	ntfy->id = watch_id;

	dprintf("data_length is %u\n", ntfy->data_length);

	queue_notify(ci, ntfy);
}

/*
 * Setup a new bs_request and queue it to the bs work queue
 *
 * 'rsp' is non-NULL if 'req' is sent from localhost
 *
 * Return 0 on success, -1 on error.
 */
static int add_bsreq(struct response *rsp, struct acrd_req *req)
{
	struct bs_request *bsreq;

	bsreq = zalloc(sizeof(struct bs_request));
	if (unlikely(!bsreq)) {
		eprintf("oom\n");
		return -1;
	}

	if (rsp) {
		list_del(&rsp->siblings);
		bsreq->rsp = rsp;
		bsreq->rq = rsp->rq;
	} else {
		bsreq->rq = malloc(sizeof(*req) + req->data_length);
		/* FIXME : error handling */
		if (unlikely(!bsreq->rq)) {
			eprintf("oom\n");
			return -1;
		}
		memcpy(bsreq->rq, req, sizeof(*req) + req->data_length);
	}

	queue_work(bs_queue, &bsreq->w_list);

	return 0;
}

/* Callbacked from main thread.
 * This function only do enquee to bs queue. */
static void __cpg_deliver(uint32_t nodeid, uint32_t pid,
			  struct acrd_common_hdr *acrd_msg)
{
	struct client_info *ci;
	struct acrd_ntfy *ntfy;
	struct response *rsp = NULL, *n;
	struct acrd_op_tmpl *op;

	switch (acrd_msg->type) {
	case ACRD_MSG_REQUEST:
		pthread_mutex_lock(&outstanding_reqs_lock);

		if (nodeid == local_nodeid && pid == getpid())
			rsp = list_first_entry(&outstanding_reqs, struct response,
					       siblings);

		add_bsreq(rsp, (struct acrd_req *)acrd_msg);

		if (rsp) {
			/* setup requests which were not casted */
			list_for_each_entry_safe(rsp, n, &outstanding_reqs,
						 siblings) {
				op = find_op(rsp->rq->opcode);
				if (op->need_mcast)
					break;

				add_bsreq(rsp, rsp->rq);
			}
		}

		pthread_mutex_unlock(&outstanding_reqs_lock);

		break;
	case ACRD_MSG_NOTIFICATION:
		/* clients management */
		update_clients_info(acrd_msg);

		list_for_each_entry(ci, &client_info_list, siblings) {
			if (ci->status != CLIENT_STATUS_JOINED)
				continue;

			ntfy = zalloc(sizeof(*ntfy));
			if (unlikely(!ntfy))
				return; /* FIXME */
			ntfy = zalloc(sizeof(*acrd_msg) +
				      acrd_msg->data_length);
			memcpy(ntfy, acrd_msg,
			       sizeof(*acrd_msg) + acrd_msg->data_length);
			ntfy = add_current_members(ntfy);

			dprintf("queued cid->id %lu\n", ci->cid.id);
			queue_notify(ci, ntfy);
		}
		break;
	}

	return;
}

#define MAX_MCAST_SIZE (256L * 1024)

static LIST_HEAD(cpg_coroutine_list);

struct cpg_coroutine {
	uint32_t nodeid;
	uint32_t pid;

	uint8_t *msg;
	size_t msg_len;
	int allocated;

	struct coroutine *co;
	struct list_head list;
};

static void cpg_co_deliver(void *opaque)
{
	struct cpg_coroutine *cpg_co = opaque;
	struct acrd_common_hdr *acrd_msg;
	int done = 0, data_length;
again:
	if (done == cpg_co->msg_len || cpg_co->msg[done] == 0xFF) {
		if (cpg_co->allocated)
			free(cpg_co->msg);
		cpg_co->msg = NULL;
		cpg_co->msg_len = 0;
		cpg_co->allocated = 0;
		done = 0;
	}

	while (cpg_co->msg_len - done < sizeof(*acrd_msg))
		coroutine_yield();

	acrd_msg = (struct acrd_common_hdr *)(cpg_co->msg + done);
	data_length = sizeof(*acrd_msg) + acrd_msg->data_length;
	while (cpg_co->msg_len - done < data_length)
		coroutine_yield();

	/* the address of cpg_co->msg may change */
	acrd_msg = (struct acrd_common_hdr *)(cpg_co->msg + done);

	__cpg_deliver(cpg_co->nodeid, cpg_co->pid, acrd_msg);

	done += data_length;

	goto again;
}

static void cpg_deliver(
	cpg_handle_t handle, const struct cpg_name *group,
	uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct cpg_coroutine *cpg_co;

	list_for_each_entry(cpg_co, &cpg_coroutine_list, list)
		if (cpg_co->nodeid == nodeid && cpg_co->pid == pid)
			goto out;

	/* create a new coroutine */
	cpg_co = zalloc(sizeof(*cpg_co));
	if (unlikely(!cpg_co)) {
		eprintf("oom\n");
		abort();
	}
	cpg_co->nodeid = nodeid;
	cpg_co->pid = pid;
	cpg_co->co = coroutine_create(cpg_co_deliver);
	list_add(&cpg_co->list, &cpg_coroutine_list);
out:
	if (unlikely(cpg_co->allocated)) {
		cpg_co->msg = realloc(cpg_co->msg, cpg_co->msg_len + msg_len);
		if (!cpg_co->msg) {
			eprintf("oom");
			abort();
		}
		memcpy(cpg_co->msg + cpg_co->msg_len, msg, msg_len);
	} else
		cpg_co->msg = msg;

	cpg_co->msg_len += msg_len;

	coroutine_enter(cpg_co->co, cpg_co);

	if (unlikely(!cpg_co->allocated && cpg_co->msg)) {
		/* preserve msg for the next cpg_deliver() call */
		cpg_co->msg = malloc(msg_len);
		if (!cpg_co->msg) {
			eprintf("oom");
			abort();
		}
		memcpy(cpg_co->msg, msg, msg_len);
		cpg_co->allocated = 1;
	}
}

struct cpg_fill_info {
	size_t len;
	void *buf;

	struct list_head *work_list;
};

static void cpg_fill_buf(void *opaque)
{
	struct cpg_fill_info *info = opaque;
	struct cpg_request *req, *n;
	struct acrd_common_hdr *hdr;
	size_t done;
	int len;

	list_for_each_entry_safe(req, n, info->work_list, w_list) {
		hdr = req->msg;
		done = 0;

		while (done < sizeof(*hdr) + hdr->data_length) {
			len = min(sizeof(*hdr) + hdr->data_length - done,
				  MAX_MCAST_SIZE - info->len);
			memcpy(info->buf + info->len, (char *)hdr + done, len);
			done += len;
			info->len += len;

			if (unlikely(info->len == MAX_MCAST_SIZE))
				coroutine_yield();
		}

		list_del(&req->w_list);
		free(req);
	}

	/* it looks like the mcast data must be aligned to 8-bytes boundary */
	len = roundup(info->len, 8);
	memset(info->buf + info->len, 0xFF, len - info->len);
	info->len = len;
}

static void cpg_mcast(struct list_head *work_list)
{
	int ret;
	struct cpg_fill_info info;
	struct coroutine *co;
	static void *buf;

	if (!buf) {
		cpg_zcb_alloc(cpg_handle, MAX_MCAST_SIZE, &buf);
		if (!buf) {
			eprintf("oom\n");
			abort();
		}
	}

	co = coroutine_create(cpg_fill_buf);

	info.buf = buf;
	info.work_list = work_list;

	while (!list_empty(work_list)) {
		info.len = 0;
		coroutine_enter(co, &info);

		dprintf("mcast_len = %zd\n", info.len);
retry:
		ret = cpg_zcb_mcast_joined(cpg_handle, CPG_TYPE_AGREED,
					   info.buf, info.len);
		if (likely(ret == CS_OK))
			continue;

		switch (ret) {
		case CS_ERR_TRY_AGAIN:
			dprintf("failed to send message. try again\n");
			goto retry;
		default:
			eprintf("failed to send message, %d\n", ret);
			break;
		}
	}
}

int init_cpg(struct cpg_name *group_name)
{
	cpg_callbacks_t cb = {&cpg_deliver, &cpg_confchg};
	int result = cpg_initialize(&cpg_handle, &cb);
	int fd;

	result = cpg_initialize(&cpg_handle, &cb);
	if (result != CS_OK) {
		eprintf("Could not initialize Cluster Process Group API"
			"instance error %d\n", result);
		return -1;
	}

	result = cpg_local_get(cpg_handle, &local_nodeid);
	if (result != CS_OK) {
		eprintf("Could not get local node id\n");
		return -1;
	}

	dprintf("Local node id is %x\n", local_nodeid);
	result = cpg_join(cpg_handle, group_name);
	if (result != CS_OK) {
		eprintf("Could not join process group, error %d\n", result);
		return -1;
	}
	cpg_fd_get(cpg_handle, &fd);

	register_event(fd, cpg_handler, NULL);

	return 0;
}

static void client_rx_handler(void *opaque)
{
	struct client_info *ci = opaque;
	struct acrd_req hdr, *req = NULL;
	struct cpg_request *cpg_req = NULL;
	struct response *rsp = NULL;
	struct acrd_op_tmpl *op;
	struct co_buffer *cob = &ci->rx_buf;
again:
	req = NULL;
	cpg_req = NULL;
	rsp = NULL;

	do_co_read(cob, &hdr, sizeof(hdr));

	req = zalloc(sizeof(hdr) + hdr.data_length);
	memcpy(req, &hdr, sizeof(hdr));

	do_co_read(cob, req->data, req->data_length);

	__sync_add_and_fetch(&ci->rx_len, req->data_length);

	/* setup response */
	rsp = alloc_response(ci, zalloc(sizeof(struct acrd_common_hdr)));
	rsp->rq = req;
	rsp->msg->id = req->id;
	rsp->msg->type = ACRD_MSG_RESPONSE;

	pthread_mutex_lock(&outstanding_reqs_lock);

	list_add_tail(&rsp->siblings, &outstanding_reqs);

	op = find_op(rsp->rq->opcode);
	if (op->need_mcast) {
		cpg_req = zalloc(sizeof(*cpg_req));
		cpg_req->msg = (struct acrd_common_hdr *)rsp->rq;

		queue_work(cpg_queue, &cpg_req->w_list);

		cpg_req = NULL; /* cpg_req will be freed in the cpg worker thread */
	} else if (list_first_entry(&outstanding_reqs, struct response, siblings) == rsp)
		/* if there is no outstanding request other than this one,
		 * we can call add_bsreq() now */
		add_bsreq(rsp, rsp->rq);

	pthread_mutex_unlock(&outstanding_reqs_lock);

	goto again;
}

static void __client_tx_handler(struct client_info *ci,
				struct list_head *rsp_list)
{
	struct response *rsp;
	int ret = 0, cnt = 0, len = 0, offset = 0, i;
	struct iovec iov[UIO_MAXIOV];

	list_for_each_entry(rsp, rsp_list, w_list) {
		if (rsp->rq) {
			__sync_sub_and_fetch(&ci->rx_len, rsp->rq->data_length);
			free(rsp->rq);
		}
		ci->tx_len += rsp->msg->data_length;

		iov[cnt].iov_base = rsp->msg;
		iov[cnt].iov_len = sizeof(*rsp->msg) + rsp->msg->data_length;
		len += iov[cnt].iov_len;
		if (++cnt == ARRAY_SIZE(iov))
			break;
	}

	while (len) {
		set_cork(ci->fd);
		ret = do_writev(ci->fd, iov, len, offset);
		unset_cork(ci->fd);

		if (ret < 0) {
			if (errno != EAGAIN)
				break;

			client_tx_on(ci);
			coroutine_yield();
			continue;
		}

		offset += ret;
		len -= ret;
	}

	if (unlikely(ret < 0)) {
		if (ci->tx_failed == 0) {
			ci->tx_failed = 1;
			ci->status = CLIENT_STATUS_DEAD;
		}
	}

	for (i = 0; i < cnt; i++) {
		rsp = list_first_entry(rsp_list, struct response, w_list);
		list_del(&rsp->w_list);
		ci->tx_len -= rsp->msg->data_length;

		free_response(rsp);
	}
}

static void client_tx_handler(void *opaque)
{
	struct client_info *ci = opaque;
	struct response *rsp;
	LIST_HEAD(list);
again:
	pthread_mutex_lock(&ci->tx_lock);
	list_splice_init(&ci->rsp_list, &list);
	pthread_mutex_unlock(&ci->tx_lock);

	while (!ci->tx_failed && !list_empty(&list))
		__client_tx_handler(ci, &list);

	if (ci->tx_failed) {
		while (!list_empty(&list)) {
			rsp = list_first_entry(&list, struct response, w_list);
			list_del(&rsp->w_list);

			free_response(rsp);
		}
	}

	pthread_mutex_lock(&ci->tx_lock);
	if (list_empty(&ci->rsp_list))
		ci->tx_on = 0;
	pthread_mutex_unlock(&ci->tx_lock);

	if (ci->tx_on == 0)
		coroutine_yield();

	goto again;
}

static struct client_info *create_client(int fd)
{
	struct client_info *ci;
	static uint32_t seq_no;

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	ci->fd = fd;
	ci->refcnt = 1;
	ci->cid.nodeid = local_nodeid;
	ci->cid.seq_no = seq_no++;
	ci->status = CLIENT_STATUS_CONNECTED;
	ci->events = EPOLLIN;
	pthread_mutex_init(&ci->tx_lock, NULL);

	dprintf("local nodeid %x fd %x, cid->nodeid %x cid->seq_no %x"
		"cid->id %lx\n", local_nodeid, fd, ci->cid.nodeid,
		ci->cid.seq_no, ci->cid.id);

	INIT_LIST_HEAD(&ci->rsp_list);

	ci->rx_co = coroutine_create(client_rx_handler);
	ci->tx_co = coroutine_create(client_tx_handler);

	list_add_tail(&ci->siblings, &client_info_list);
	dprintf("ci %p", ci);
	notify_node_event(ci->cid.id, ACRD_EVENT_JOINED);

	return ci;
}

static void recv_request(struct list_head *work_list)
{
	struct client_info *ci, *n;
	int ret;
	char buf[1048576];

	list_for_each_entry_safe(ci, n, work_list, rx_list) {
		list_del(&ci->rx_list);

		ret = do_read(ci->fd, buf, sizeof(buf));
		if (likely(ret >= 0)) {
			ci->rx_buf.offset = 0;
			ci->rx_buf.len = ret;
			ci->rx_buf.buf = buf;

			coroutine_enter(ci->rx_co, ci);

			if (too_many_requests(ci))
				ci->stop = 1;
			else
				client_rx_on(ci);
		} else
			ci->status = CLIENT_STATUS_DEAD;

		client_decref(ci);
	}
}

static void send_response(struct list_head *work_list)
{
	struct client_info *ci, *n;

	list_for_each_entry_safe(ci, n, work_list, tx_list) {
		list_del(&ci->tx_list);
		assert(ci->tx_on == 1);

		coroutine_enter(ci->tx_co, ci);

		if (!ci->tx_failed && ci->stop && !too_many_requests(ci)) {
			ci->stop = 0;
			client_rx_on(ci);
		}

		client_decref(ci);
	}
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;

	if (events & EPOLLIN) {
		assert(ci->rx_list.next == NULL);

		client_rx_off(ci);

		client_incref(ci);
		queue_work(recv_queue[fd % NR_RECV_THREAD], &ci->rx_list);
	}

	if (events & EPOLLOUT) {
		pthread_mutex_lock(&ci->tx_lock);

		ci->tx_on = 1;
		client_tx_off(ci);

		client_incref(ci);
		queue_work(send_queue[fd % NR_SEND_THREAD], &ci->tx_list);

		pthread_mutex_unlock(&ci->tx_lock);
	}

	if (ci->status == CLIENT_STATUS_DEAD) {
		eprintf("closed a connection, %d\n", fd);
		pthread_mutex_lock(&event_lock);
		unregister_event(fd);
		pthread_mutex_unlock(&event_lock);

		remove_all_watch(ci);

		list_del(&ci->siblings);
		notify_node_event(ci->cid.id, ACRD_EVENT_LEFT);

		client_decref(ci);
	}
}

static void listen_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		eprintf("can't accept a new connection, %m\n");
		return;
	}

	ret = set_nodelay(fd);
	if (ret) {
		close(fd);
		return;
	}

	ret = set_nonblocking(fd);
	if (ret) {
		close(fd);
		return;
	}

	ret = set_keepalive(fd, keepidle, keepintvl, keepcnt);
	if (ret) {
		close(fd);
		return;
	}

	ci = create_client(fd);
	if (!ci) {
		close(fd);
		return;
	}

	pthread_mutex_lock(&event_lock);
	ret = register_event(fd, client_handler, ci);
	pthread_mutex_unlock(&event_lock);
	if (ret) {
		destroy_client(ci);
		return;
	}

	dprintf("accepted a new connection, %d ci->fd %d ci %p\n",
		fd, ci->fd, ci);
}

static int create_listen_port_fn(int fd, void *data)
{
	return register_event(fd, listen_handler, data);
}

int create_listen_port(int port, void *data)
{
	return create_listen_ports(port, create_listen_port_fn, data);
}

int init_acrd_work_queue(int in_memory)
{
	int i;

	for (i = 0; i < NR_RECV_THREAD; i++) {
		recv_queue[i] = init_work_queue(recv_request, RECV_INTERVAL);
		if (!recv_queue[i])
			return -1;
	}

	for (i = 0; i < NR_SEND_THREAD; i++) {
		send_queue[i] = init_work_queue(send_response, SEND_INTERVAL);
		if (!send_queue[i])
			return -1;
	}

	bs_queue = init_work_queue(bs_exec_request, 0);
	if (!bs_queue)
		return -1;

	cpg_queue = init_work_queue(cpg_mcast, CPG_INTERVAL);
	if (!cpg_queue)
		return -1;

	if (!in_memory) {
		sync_queue = init_work_queue(bs_sync, SYNC_INTERVAL);
		if (!sync_queue)
			return -1;
	}

	return 0;
}
