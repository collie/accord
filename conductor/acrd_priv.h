#ifndef __SERV_PRIV_H__
#define __SERV_PRIV_H__

#include "list.h"

#define RECV_INTERVAL 1 /* ms */
#define SEND_INTERVAL 1 /* ms */
#define CPG_INTERVAL 1 /* ms */
#define SYNC_INTERVAL 20 /* ms */

#define NR_RECV_THREAD 8
#define NR_SEND_THREAD 8

#define MAX_MULTI_REQS 4096

struct acrd_txid;
struct client_info;

struct acrd_op_tmpl {
	enum OPERATION opcode;

	int need_mcast;

	int (*exec_req)(const struct acrd_req *req, struct acrd_rsp **rsp,
			struct acrd_txid *txid, struct client_info *from);
	void (*exec_multi_reqs)(const struct acrd_req **reqs, struct acrd_rsp ***rsps,
				int *ret, size_t nr, struct acrd_txid *txid);
	void (*notify_event)(const struct acrd_req *req);
};

void remove_all_watch(struct client_info *ci);

int init_cpg(struct cpg_name *group_name);
void cpg_handler(int fd, int events, void *arg);

void do_notify_event(const struct acrd_req *req, uint16_t events,
		     uint32_t watch_id, struct client_info *ci);
int create_listen_port(int port, void *data);

int init_acrd_work_queue(int in_memory);

struct acrd_op_tmpl *find_op(enum OPERATION opcode);

#endif
