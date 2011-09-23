#ifndef __ACCORD_H__
#define __ACCORD_H__

#include "proto.h"
#include "list.h"
#include "net.h"

struct acrd_handle;
struct acrd_tx;
struct acrd_watch_info;
struct acrd_aiocb;

typedef void (*acrd_watch_cb_t)(struct acrd_handle *bh,
			       struct acrd_watch_info *info, void *arg);


/**
 * Callback function definition when a client joined/left.
 * Argument description is as follows :
 *
 * 'member_list' 		Array of connecting clients id.
 * 'member_list_entries' 	A size of array member_list.
 * 'nodeid' :			A client id of left/joined node.
 * 				It is assured that the first callback of
 * 				join_cb from servers contains assigned nodeid from
 *				Accord servers.
 * 'arg' 			An argument pointer which is set when acrd_init() is called.
 *				return value is handler to call the other Accord APIs.
 */
typedef void (*acrd_confchg_cb_t)(struct acrd_handle *bh,
				 const uint64_t *member_list,
				 size_t member_list_entries, uint64_t nodeid,
				 void *arg);



typedef void (*acrd_aio_cb_t)(struct acrd_handle *bh, struct acrd_aiocb *aiocb,
			     void *arg);
typedef void (*acrd_list_cb_t)(struct acrd_handle *bh, const char *path,
			      void *arg);

struct acrd_watch_info {
	struct acrd_handle *handle;
	const char *path; /* path the event occurs*/
	const void *data;
	unsigned int data_len;
	uint64_t offset; /* The changed file location */
	void *ctx;
	uint16_t events; /* An occured event number */
	acrd_watch_cb_t cb;
	uint32_t id;
	uint32_t mask;

	struct list_head list;
};

struct acrd_aiocb {
	struct acrd_handle *handle;
	int done;
	uint32_t result;
	acrd_aio_cb_t cb;
	void *arg;
};

struct acrd_listcb {
	acrd_list_cb_t cb;
	void *arg;
};

/**
 * Create a new connection to the Accord servers
 *
 * This function is used to initialize a connection to the Accord
 * service.  Each application may have several connections to the
 * Accord.  This function returns a handle to uniquely identify the
 * connection.  The handle is used in other function calls to identify
 * the connection to be used for communication with Accord.
 *
 * Every time other clients join to or leave from Accord, the
 * specified callback function, join_cb or leave_cb, is called.
 *
 * Returns a created handle on success, NULL on error,
 * See also : acrd_confchg_cb_t
 */
struct acrd_handle *acrd_init(const char *hostname, int port,
			    acrd_confchg_cb_t join_cb, acrd_confchg_cb_t leave_cb,
			    void *arg);

/**
 * Terminate a connection to the Accord servers
 *
 * This function closes a Accord handle and free up any resources.
 * Once the connection is closed, the handle may not be used again by
 * applications.  No more callbacks will be called after this function
 * is called.
 *
 * Returns zero on success, -1 on error.
 */
int acrd_close(struct acrd_handle *handle);


/* Accord I/O API */

/**
 * Write data to Accord
 *
 * This writes up to 'count' bytes from the buffer starting at 'data'.
 * The destination to save is a file 'path', 'offset' bytes.
 * This function blocks until the operation has been completed.
 *
 * Supported flags are as follows:
 *
 * ACRD_FLAG_CREATE
 *   Create a new file on Accord. If a path has already exists, return
 *   ACRD_ERR_EXIST.
 *
 * ACRD_FLAG_EXCL
 *   Writes the file wether the file is exist or not.
 *
 * ACRD_FLAG_APPEND
 *   If set, the file offset will be set to the end of the file prior to each write.
 *
 * ACRD_FLAG_SYNC
 *    Writes IO is reported as completed after it has been flushed to the disks.
 *    If NOT set ACRD_FLAG_SYNC, a response is returned when all servers are assured to
 *    receive the write request.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_NOTFOUND if the specified
 * path does not exist but ACRD_FLAG_CREATE is not set to flags,
 * ACRD_ERR_EXIST if the specified path exists bug ACRD_FLAG_CREATE is
 * set to flags.
 *
 */
int acrd_write(struct acrd_handle *h, const char *path, const void *data,
	      uint32_t count, uint64_t offset, uint32_t flags);

/**
 * Read data from Accord
 *
 * The source to read is a file 'path', 'offset' bytes.
 *
 * This function blocks until the operation has been completed.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_NOTFOUND if the specified
 * path is not found.
 */
int acrd_read(struct acrd_handle *h, const char *path, void *data,
	     uint32_t *count, uint64_t offset, uint32_t flags);

/**
 * Delete the specified data from Accord
 *
 * This function blocks until the operation has been completed.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_NOTFOUND if the specified
 * path is not found.
 */
int acrd_del(struct acrd_handle *h, const char *path, uint32_t flags);

/**
 * Do a prefix search and list matching keys
 *
 * This function blocks until the operation has been completed.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_list(struct acrd_handle *h, const char *prefix, uint32_t flags,
	     struct acrd_listcb *listcb);

/**
 * Copy data on the Accord server
 *
 * This function blocks until the operation has been completed.
 *
 * On success, ACRD_SUCCESS is returned.  If the src path is not found,
 * or the dst path does not exist but ACRD_FLAG_CREATE is not set to
 * flags, ACRD_ERR_NOTFOUND is returned.  Returns ACRD_ERR_EXIST if the
 * dst path exists bug ACRD_FLAG_CREATE is set to flags
 */
int acrd_copy(struct acrd_handle *h, const char *src, const char *dst,
	     uint32_t flags);


/* Accord asynchronous I/O API */

/**
 * Create an asynchronous I/O control block
 *
 * This function creates an asynchronous I/O control block for the
 * asyncronous operation.  Every AIO operations needs the aiocb
 * returned by this function.  Each AIO operation is identified with
 * the aiocb.  If you want to wait one of the AIO operations, call
 * acrd_aio_wait() with its aiocb.
 *
 * Returns a created aiocb on success, NULL on error.
 */
struct acrd_aiocb *acrd_aio_setup(struct acrd_handle *h, acrd_aio_cb_t cb,
				void *arg);

/**
 * Release an asynchronous I/O control block
 *
 * This function free up any resources used by the aiocb.  This may
 * not be called before the AIO operation is finished.  To ensure that
 * the operation is done, call acrd_aio_wait().
 */
void acrd_aio_release(struct acrd_handle *h, struct acrd_aiocb *aiocb);

/**
 * Wait for the AIO operation to be completed
 *
 * This function will wait until the specified AIO operation has
 * completed.
 */
void acrd_aio_wait(struct acrd_handle *h, struct acrd_aiocb *aiocb);

/**
 * Flush AIO operations
 *
 * This function flushes all pending AIO operations.  This will block
 * until all outstanding AIO operations have been completed.
 */
void acrd_aio_flush(struct acrd_handle *h);

/**
 * Write data to Accord asynchronously
 *
 * This is the asynchronous version of acrd_write().  This call returns
 * as soon as the request has been enqueued.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 * See also : acrd_write()
 */
int acrd_aio_write(struct acrd_handle *h, const char *path, const void *data,
		  uint32_t count, uint64_t offset, uint32_t flags,
		  struct acrd_aiocb *aiocb);

/**
 * Read data from Accord asynchronously
 *
 * This is the asynchronous version of acrd_read().  This call returns
 * as soon as the request has been enqueued.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 * See also : acrd_read()
 */
int acrd_aio_read(struct acrd_handle *h, const char *path, void *data,
		 uint32_t *count, uint64_t offset, uint32_t flags,
		 struct acrd_aiocb *aiocb);

/**
 * Delete the specified data from Accord asynchronously
 *
 * This is the asynchronous version of acrd_del().  This call returns
 * as soon as the request has been enqueued.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_aio_del(struct acrd_handle *h, const char *path, uint32_t flags,
		struct acrd_aiocb *aiocb);

/**
 * Do a prefix search and list matching keys asynchronously
 *
 * This is the asynchronous version of acrd_list().  This call returns
 * as soon as the request has been enqueued.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_aio_list(struct acrd_handle *h, const char *prefix, uint32_t flags,
		 struct acrd_listcb *listcb, struct acrd_aiocb *aiocb);

/**
 * Copy data on the Accord server asynchronously
 *
 * This is the asynchronous version of acrd_copy().  This call returns
 * as soon as the request has been enqueued.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_aio_copy(struct acrd_handle *h, const char *src, const char *dst,
		 uint32_t flags, struct acrd_aiocb *aiocb);


/* Accord transaction API */

/**
 * Create a new transaction
 *
 * This function allocate transaction descriptor acrd_tx.
 * Note that acrd_tx_init() function doesn't start transaction
 * but just allocate memory for a new transaction.
 *
 * Returns a created acrd_tx on success, NULL on error.
 */
struct acrd_tx *acrd_tx_init(struct acrd_handle *h);

/**
 * Close a transaction
 *
 * This function closes a transaction and free up any resources.
 */
void acrd_tx_close(struct acrd_tx *tx);

/**
 * Add a write operation to the transaction
 *
 * This function is similar to acrd_write() but only used for a
 * transaction.  If the operation fails, the transaction will be
 * aborted.  This call returns as soon as the request has been added
 * to the transaction.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_tx_write(struct acrd_tx *tx, const char *path, const void *buf,
		 uint32_t count, uint64_t offset, uint32_t flags);

/**
 * Add a read operation to the transaction
 *
 * This function is similar to acrd_read() but only used for a
 * transaction.  If the operation fails, the transaction will be
 * aborted.  This call returns as soon as the request has been added
 * to the transaction.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_tx_read(struct acrd_tx *tx, const char *path, void *buf, uint32_t *count,
		uint64_t offset, uint32_t flags);

/**
 * Add a delete operation to the transaction
 *
 * This function is similar to acrd_del() but only used for a
 * transaction.  If the operation fails, the transaction will be
 * aborted.  This call returns as soon as the request has been added
 * to the transaction.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_tx_del(struct acrd_tx *tx, const char *path, uint32_t flags);

/**
 * Add a compare operation to the transaction
 *
 * This add a operation to compare data to a transaction.  If the
 * content of 'path' doesn't equal to the first 'count' bytes of
 * 'buf', the transaction will be aborted.  This call returns as soon
 * as the request has been added to the transaction.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_tx_cmp(struct acrd_tx *tx, const char *path, const void *buf,
	       uint32_t count, uint32_t flags);

/**
 * Add a server-side compare operation to the transaction
 *
 * This add a operation to compare data to a transaction.  If the
 * content of 'path1' doesn't equal to the one of 'path2', the
 * transaction will be aborted.  This call returns as soon as the
 * request has been added to the transaction.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_tx_scmp(struct acrd_tx *tx, const char *path1, const char *path2,
		uint32_t flags);

/**
 * Add a copy operation to the transaction
 *
 * This function is similar to acrd_copy() but only used for a
 * transaction.  If the operation fails, the transaction will be
 * aborted.  This call returns as soon as the request has been added
 * to the transaction.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 */
int acrd_tx_copy(struct acrd_tx *tx, const char *src, const char *dst,
		uint32_t flags);

/**
 * Commit a transaction
 *
 * This function commits a transaction.  The maximum number of
 * operations which can be commited at once is 65535.
 *
 * If the transaction is commited, this returns ACRD_SUCCESS.  If the
 * transaction is aborted, this returns the error code(abort reason).
 * Transaction related errors is as follows:
 *
 * acrd_tx_cmp() abort : ACRD_ERR_EXIST
 * acrd_tx_write() abort : ACRD_ERR_NOTFOUND/ACRD_ERR_EXIST/ACRD_ERR_STORE
 */
int acrd_tx_commit(struct acrd_tx *tx, uint32_t flags);

/**
 * Commit a transaction asynchronously
 *
 * This is the asynchronous version of acrd_tx_commit().  This function
 * returns as soon as the request has been enqueued.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_UNKNOWN on error.
 *
 * See also : acrd_aio_setup(), acrd_tx_commit()
 */
int acrd_tx_aio_commit(struct acrd_tx *tx, uint32_t flags,
		      struct acrd_aiocb *aiocb);


/* Accord watch API */

/**
 * Start monitoring data on the Accord server
 *
 * This starts monitoring data change events.  The events to be
 * monitored for 'path' are specified in the 'mask' bit-mask argument.
 * The following bits can be specified in 'mask':
 *
 *     ACRD_EVENT_CREATED    Data is created
 *     ACRD_EVENT_DELETED    Data is deleted
 *     ACRD_EVENT_CHANGED    Data is changed
 *     ACRD_EVENT_COPIED     Data is copied
 *     ACRD_EVENT_ALL        A bit mask of all of the above events
 *
 * If you set EVENT_PREFIX flag to the mask, you can watch multiple
 * files which start with 'path'.
 *
 * This returns acrd_watch_info on success, NULL on error.
 */
struct acrd_watch_info *acrd_add_watch(struct acrd_handle *h, const char *path,
				     uint32_t mask, acrd_watch_cb_t cb,
				     void *arg);

/**
 * Stop monitoring data on the Accord server
 *
 * This function removes the registered acrd_watch_info from ths Accord
 * server.
 *
 * Returns ACRD_SUCCESS on success, ACRD_ERR_NOTFOUND if the specified
 * acrd_watch_info is not registerd on the Accord server.
 */
int acrd_rm_watch(struct acrd_handle *h, struct acrd_watch_info *bw);

#endif /* __ACCORD_H__ */
