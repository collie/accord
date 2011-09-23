#ifndef __WORK_H__
#define __WORK_H__

#include "list.h"

struct work;
struct work_queue;

typedef void (*work_func_t)(struct list_head *);

struct work_queue *init_work_queue(work_func_t fn, int interval);
void queue_work(struct work_queue *wq, struct list_head *w_list);
void exit_work_queue(struct work_queue *wq);

#endif
