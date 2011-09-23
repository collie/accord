#ifndef __STORE_H__
#define __STORE_H__

#include <db.h>

struct acrd_txid {
	DB_TXN *tid;
};

struct store_req_vec {
	char *key;
	const void *data;
	uint32_t data_len;
};

int store_init(const char *rootdir, int in_memory_mode);
int store_read(const char *key, void **data, uint32_t *data_len,
	       uint64_t offset, struct acrd_txid *txid);
int store_writev(struct store_req_vec *vec, int nr);
int store_write(const char *key, const void *data, uint32_t data_len,
		uint64_t offset, uint32_t flags, struct acrd_txid *txid);
int store_sync(void);
int store_del(const char *key, struct acrd_txid *txid);
int store_list(const char *key, int (*add_file)(const char *, void *),
	       void *opaque, struct acrd_txid *txid);
int store_tx_begin(struct acrd_txid *tx);
int store_tx_commit(struct acrd_txid *tx);
int store_tx_abort(struct acrd_txid *tx);
int store_close(void);
#endif /* __STORE_H__*/
