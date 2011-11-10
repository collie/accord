#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>

#include <accord.h>
#include "util.h"
#include "coroutine.h"
#include "adler32.c"

#define NR_THREADS 100

static char *hostname;
static int port;

struct acrd_path_list_entry {
	char *path;

	struct list_head list;
};

struct queue_handle {
	struct acrd_handle *ah;
	char name[128];
};

struct queue_msg {
	uint32_t len;
	uint32_t checksum;
	char data[0];
};

struct ack_info {
	char *invisible_path;
};

static void test_concurrent_list_cb(struct acrd_handle *h, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static int create_first_nodes(struct acrd_handle *h)
{
	int max = 1;
	int ret;
	struct acrd_tx *tx;

	tx = acrd_tx_init(h);

retry:
	acrd_tx_write(tx, "/tmp/queue/min", &max, sizeof(max), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	acrd_tx_write(tx, "/tmp/queue/max", &max, sizeof(max), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	ret = acrd_tx_commit(tx, 0);

	if (ret != ACRD_SUCCESS && ret != ACRD_ERR_EXIST) {
		if (ret == ACRD_ERR_AGAIN) {
			goto retry;
		} else
			printf("%d:unknown err %d.\n", __LINE__, ret);
	}
	acrd_tx_close(tx);
	return 0;
}

struct queue_handle *queue_init(const char *hostname, int port, const char *name)
{
	struct queue_handle *qh;
	struct acrd_handle *ah;

	ah = acrd_init(hostname, port, NULL, NULL, NULL);
	qh = zalloc(sizeof(struct queue_handle));

	if (!qh || !ah)
		return NULL;

	qh->ah = ah;
	create_first_nodes(ah);
	return qh;
}

void queue_close(struct queue_handle *qh)
{
	acrd_close(qh->ah);
	free(qh);

	return;
}

inline uint32_t calc_checksum(void *data, uint32_t len)
{
	const uint32_t adler = 1;
	return adler32(adler, data, len);;
}

inline uint32_t get_msghdr_size(void)
{
	return sizeof(struct queue_msg);
}

int queue_push(struct queue_handle *qh, void *data, uint32_t len)
{
	struct acrd_tx *tx;
	char retdata[32];
	uint32_t size, max;
	int ret;
	char path[256];
	struct acrd_handle *h = qh->ah;
	uint32_t delta = 1;
	struct queue_msg *qe;

	qe = zalloc(sizeof(struct queue_msg) + len);
	memcpy(qe->data, data, len);
	qe->len = len;
	qe->checksum = calc_checksum(qe->data, qe->len);
	//printf("len %d checksum %d data %s \n", qe->len, qe->checksum, qe->data);

	size = sizeof(retdata);
retry1:
	assert(max > 0);

	tx = acrd_tx_init(h);
	acrd_tx_atomic_inc(tx, "/tmp/queue/max", &delta,
			sizeof(uint32_t), 0, 0);
	acrd_tx_read(tx, "/tmp/queue/max", &retdata, &size, 0, 0);
	ret = acrd_tx_commit(tx, 0);
	if (ret != ACRD_SUCCESS) {
		if (ret == ACRD_ERR_AGAIN)
			goto retry1;
		else
			printf("%d:unknown err %d.\n", __LINE__, ret);
	}
	acrd_tx_close(tx);
	memcpy(&max, retdata, sizeof(max));
	sprintf(path, "/tmp/queue/%d", max - 1);
	//printf("max %d\n", max);
	//printf("wrote data path %s len %d checksum %d data %s \n", path, qe->len, qe->checksum, qe->data);

retry2:
	ret = acrd_write(h, path, qe, get_msghdr_size() + len, 0,
			     ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	if (ret != ACRD_SUCCESS) {
		if (ret == ACRD_ERR_AGAIN)
			goto retry2;
		else {
			printf("write err?\n");
			free(qe);
			return -1;
		}
	}
	return 0;
}

int queue_pop(struct queue_handle *qh, struct queue_msg **retqe)
{
	struct acrd_handle *h = qh->ah;
	struct acrd_tx *tx;
	int delta = 1, min = 0, ret;
	char path[256];
	char min_buf[32];
	uint32_t size = sizeof(uint32_t);
	uint32_t min_size = sizeof(uint32_t);
	uint32_t checksum;
	uint32_t qe_size;
	uint64_t offset;
	struct queue_msg *qe;

	*retqe = NULL;
	qe = zalloc(sizeof(struct queue_msg));
	qe_size = sizeof(*qe);

	if (qe == NULL) {
		printf("oom\n");
		return -1;
	}
retry1:
	tx = acrd_tx_init(h);
	acrd_tx_read(tx, "/tmp/queue/min", min_buf, &min_size, 0, 0);
	acrd_tx_atomic_inc(tx, "/tmp/queue/min", &delta,
		sizeof(uint32_t), 0, 0);
	ret = acrd_tx_commit(tx, 0);
	acrd_tx_close(tx);
	switch (ret) {
	case ACRD_SUCCESS:
		break;
	case ACRD_ERR_AGAIN:
		goto retry1;
	case ACRD_ERR_NOTFOUND:
	default:
		printf("the node min is not found\n");
		free(qe);
		return -1;
	}

	if (size != sizeof(min)) {
		printf("the read min size error\n");
		return -1;
	}

	memcpy(&min, min_buf, sizeof(min));
	//printf("min %d max %d\n", min, max);
	if (min < 0) {
		printf("min value error\n");
		return -1;
	}

	sprintf(path, "/tmp/queue/%d", min);
	//printf("path %s min %d max %d\n", path, min, max);

retry2:
	ret = acrd_read(h, path, qe, &qe_size, 0, 0);
	if (ret != ACRD_SUCCESS) {
		if (ret == ACRD_ERR_AGAIN)
			goto retry2;
		else {
			printf("%d:unknown err %d.\n", __LINE__, ret);
			return -1;
		}
	}

	/* read body */
	qe = realloc(qe, get_msghdr_size() + qe->len);
	qe_size = qe->len;
	offset = get_msghdr_size();
retry3:
	ret = acrd_read(h, path, qe->data, &qe_size, offset, 0);
	if (ret != ACRD_SUCCESS) {
		if (ret == ACRD_ERR_AGAIN)
			goto retry3;
		else {
			printf("%d:unknown err %d.\n", __LINE__, ret);
			return -1;
		}
	}

	checksum = calc_checksum(qe->data, qe->len);
	//printf("len %d checksum %d data %s\n", qe->len, qe->checksum, qe->data);

	if (qe->checksum != checksum) {
		printf("Read corrupt data\n");
		printf("path %s data %s len %d checksum %d, calc value : %d\n",
		path, qe->data, qe->len,
		qe->checksum, checksum);
		return -1;
	}
	*retqe = qe;

	/* FIXME: it is better to call queue_ack() */
	ret = acrd_del(h, path, 0);

	return 0;
}

int queue_ack(struct queue_handle *qh, struct ack_info *info)
{
	int ret;
	struct acrd_handle *h = qh->ah;
	char *inv_path = info->invisible_path;

	ret = acrd_del(h, inv_path, 0);
	if (ret != ACRD_SUCCESS)
		return -1;

	free(info->invisible_path);
	free(info);
	return 0;
}

void queue_msg_close(struct queue_msg *msg)
{
	free(msg);
}

static void *run(void *arg)
{
	struct queue_handle *h;
	const char *qname = "hoge";
	char data[128] = "the contents of data";
	uint32_t size = strlen(data) + 1;
	struct queue_msg *msg;
	int reqs, i;

	reqs = *(int *)arg;
	h  = queue_init(hostname, port, qname);
	if (h == NULL) {
		printf("failed to exit...");
		goto exit;
	}

	/* very simple test case */
	for (i = 0; i < reqs; i++) {
		queue_push(h, data, size);
		if (queue_pop(h, &msg) == 0) {
			if (msg)
				queue_msg_close(msg);
		}
	}
	printf("exit.\n");

	/* cleanup */
	queue_close(h);

exit:
	pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
	int ret, i, nr_threads, nr_requests;
	struct acrd_handle *h;
	LIST_HEAD(path_list);
	struct acrd_listcb listcb = {
		.cb = test_concurrent_list_cb,
		.arg = &path_list,
	};
	struct acrd_path_list_entry *entry, *n;
	struct timeval start, end, total;
	double throughput;

	pthread_t *th;

	if (argc < 5) {
		printf("usage: ./qbench [hostname] [port] [nr_threads] [nr_requests]\n");
		exit(1);
	}

	hostname = argv[1];
	port = atoi(argv[2]);
	nr_threads = atoi(argv[3]);
	nr_requests = atoi(argv[4]);
	th = malloc(sizeof(pthread_t)*nr_threads);
	if (!th) {
		printf("oom\n");
		exit(1);
	}

	gettimeofday(&start, NULL);
	for (i = 0; i < nr_threads; i++) {
		ret = pthread_create(&th[i], NULL, run, &nr_requests);
		if (ret < 0) {
			printf("failed to init threads.\n");
			exit(1);
		}
	}

	for (i = 0; i < nr_threads; i++)
		pthread_join(th[i], NULL);

	gettimeofday(&end, NULL);
	timersub(&end, &start, &total);
	throughput = (nr_requests * nr_threads) /
		(total.tv_sec + ((double)total.tv_usec)/1000000.0);

	printf("\n%d requests in %d.%06d sec. (%.2f throughput)\n",
		nr_requests * nr_threads, (int)total.tv_sec, (int)total.tv_usec,
		throughput);

	/* cleanup data */
	h = acrd_init(hostname, port, NULL, NULL, NULL);
	acrd_list(h, "/tmp/", 0, &listcb);
	list_for_each_entry_safe(entry, n, &path_list, list) {
		acrd_del(h, entry->path, 0);
		free(entry->path);
		list_del(&entry->list);
		free(entry);
	}
	acrd_close(h);
	return 0;
}
