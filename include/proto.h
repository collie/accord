#ifndef __PROTO_H__
#define __PROTO_H__

#include "stdint.h"
#include "util.h"

enum TYPE {
	ACRD_MSG_REQUEST = 0x00,
	ACRD_MSG_RESPONSE,
	ACRD_MSG_NOTIFICATION
};

enum OPERATION {
	ACRD_OP_WRITE = 0x00,
	ACRD_OP_READ,
	ACRD_OP_DEL,
	ACRD_OP_TX,
	ACRD_OP_CMP,
	ACRD_OP_SCMP,
	ACRD_OP_COPY,
	ACRD_OP_LIST,
	ACRD_OP_ADD_WATCH,
	ACRD_OP_RM_WATCH,
	ACRD_OP_INVALID /* this op shouldn't be called */
};

enum RESULT {
	ACRD_SUCCESS = 0,

	/* unknown */
	ACRD_ERR_UNKNOWN = 0x10,

	/*  common error */
	ACRD_ERR_AGAIN = 0x20,

	/*  tcp connection error */
	ACRD_ERR_CONN = 0x30,
	ACRD_ERR_CONN_TIMEOUT,
	ACRD_ERR_CONN_REFUSED,

	/*  msg related error */
	ACRD_ERR_MSG = 0x40,
	ACRD_ERR_MSG_HDR,

	/* bdb related error */
	ACRD_ERR_STORE = 0x50,
	ACRD_ERR_EXIST,
	ACRD_ERR_NOTFOUND,
	ACRD_ERR_NOTEQUAL,
};


#define ACRD_EVENT_NONE          0x00000000

#define ACRD_EVENT_CREATED       0x00000001
#define ACRD_EVENT_DELETED       0x00000002
#define ACRD_EVENT_CHANGED       0x00000004
#define ACRD_EVENT_COPIED        0x00000008
#define ACRD_EVENT_ALL           0x000000FF
#define ACRD_EVENT_WATCH_MASK    0x000000FF

#define ACRD_EVENT_JOINED        0x00000100
#define ACRD_EVENT_LEFT          0x00000200
#define ACRD_EVENT_CONFCHG_MASK  0x0000FF00

#define ACRD_EVENT_PREFIX        0x01000000


#define ACRD_FLAG_SYNC           0x0001 /* write IO is reported as completed,
					* after it has been flushed to the disks. */
#define ACRD_FLAG_CREATE         0x0002
#define ACRD_FLAG_APPEND         0x0004
#define ACRD_FLAG_EXCL           0x0008

/**
 * operation arguments
 * PUT : path, data
 * GET : path
 * DEL : path
 * TX  : acrd_msg
 */


/**
 * msg format :
 *   acrd_msg |hdr|
 *   arg1    |size|data|
 *   arg2    |size|data|
 *   arg3    |size|data|
 *
 * Sample : normal ops case
 *   write(fd, hdr, sizeof(acrd_msg));
 *   write(fd, arg1->size, sizeof(uint32_t));
 *   write(fd, arg1->data, sizeof(arg1->size));
 *   write(fd, arg2->size, sizeof(uint32_t));
 *   write(fd, arg2->data, sizeof(arg2->size));
 * ...
 * Sample2 : transaction case
 *   write(fd, hdr, sizeof(acrd_msg));
 *   write(fd, hdr1, sizeof(acrd_msg));
 *   write(fd, hdr2, sizeof(acrd_msg));
 *   write(fd, arg1->size, sizeof(uint32_t));
 *   write(fd, arg1->data, sizeof(arg1->size));
 *   write(fd, arg2->size, sizeof(uint32_t));
 *   write(fd, arg2->data, sizeof(arg2->size));
 *
 */

struct acrd_common_hdr {
	uint8_t         proto_ver;
	uint8_t         type;
	uint16_t        rsvd;
	uint32_t        data_length; /* entire data length without hdr */
	uint64_t        offset;
	uint32_t        id;

	uint32_t        type_specific[3];

	uint8_t         data[0];
};

struct acrd_req {
	uint8_t         proto_ver;
	uint8_t         type;
	uint16_t        rsvd;
	uint32_t        data_length;
	uint64_t        offset;
	uint32_t        id;

	/* request specific header */
	uint8_t         opcode;
	uint8_t         rsvd2;
	uint16_t        flags;
	uint32_t        size;
	uint32_t        rsvd3;

	uint8_t         data[0];
};

struct acrd_rsp {
	uint8_t         proto_ver;
	uint8_t         type;
	uint16_t        rsvd;
	uint32_t        data_length;
	uint64_t        offset;
	uint32_t        id;

	/* response specific header */
	int32_t	        result;
	int64_t         rsvd2;

	uint8_t         data[0];
};

struct acrd_ntfy {
	uint8_t         proto_ver;
	uint8_t         type;
	uint16_t        rsvd;
	uint32_t        data_length;
	uint64_t        offset;
	uint32_t        id;

	/* notification specific header */
	uint16_t        events;
	uint16_t        rsvd2;
	int64_t         rsvd3;

	uint8_t         data[0];
};


struct acrd_arg {
	uint32_t        size;
	char            data[0];
};

#define for_each_arg(arg, hdr)						\
	for (arg = (struct acrd_arg *)hdr->data;				\
	     (uint8_t *)arg < (hdr)->data + (hdr)->data_length;		\
	     arg = (struct acrd_arg *)((uint8_t *)arg +			\
				      sizeof(arg->size) + arg->size))

/* Get the idx'th argument */
static inline const struct acrd_arg *get_arg(const void *p, int idx)
{
	const struct acrd_common_hdr *hdr = p;
	const struct acrd_arg *arg;
	int i = 0;

	for_each_arg(arg, hdr) {
		if (i == idx)
			return arg;
		i++;
	}

	return NULL;
}

/* Add a new argument */
static inline void *add_arg(void *p, const void *data, uint32_t data_len)
{
	struct acrd_common_hdr *hdr = p;
	struct acrd_arg *arg;

	hdr = realloc(hdr, sizeof(*hdr) + hdr->data_length +
		      sizeof(data_len) + data_len);
	if (unlikely(!hdr)) {
		fprintf(stderr, "oom\n");
		return NULL;
	}

	arg = (struct acrd_arg *)(hdr->data + hdr->data_length);
	arg->size = data_len;
	memcpy(arg->data, data, data_len);

	hdr->data_length += sizeof(data_len) + data_len;

	return hdr;
}

/* Append data to the last argument.  This doesn't add a new argument */
static inline void *append_arg(void *p, const void *data, uint32_t data_len)
{
	struct acrd_common_hdr *hdr = p;
	struct acrd_arg *arg, *last_arg = NULL;

	if (hdr->data_length == 0)
		return add_arg(p, data, data_len);

	hdr = realloc(hdr, sizeof(*hdr) + hdr->data_length + data_len);
	if (unlikely(!hdr)) {
		fprintf(stderr, "oom\n");
		return NULL;
	}

	for_each_arg(arg, hdr)
		last_arg = arg;

	memcpy(last_arg->data + last_arg->size, data, data_len);
	last_arg->size += data_len;

	hdr->data_length += data_len;

	return hdr;
}

#endif /* __PROTO_H__ */
