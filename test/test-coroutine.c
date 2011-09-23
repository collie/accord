/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * This code is based on test-coroutine.c from QEMU:
 *   Copyright (C) 2011 Stefan Hajnoczi <stefanha@linux.vnet.ibm.com>
 */

#include <glib.h>
#include "coroutine.h"

/*
 * Check that in_coroutine() works
 */

static void verify_in_coroutine(void *opaque)
{
	g_assert(in_coroutine());
}

static void test_in_coroutine(void)
{
	struct coroutine *coroutine;

	g_assert(!in_coroutine());

	coroutine = coroutine_create(verify_in_coroutine);
	coroutine_enter(coroutine, NULL);
}

/*
 * Check that coroutine_self() works
 */

static void verify_self(void *opaque)
{
	g_assert(coroutine_self() == opaque);
}

static void test_self(void)
{
	struct coroutine *coroutine;

	coroutine = coroutine_create(verify_self);
	coroutine_enter(coroutine, coroutine);
}

/*
 * Check that coroutines may nest multiple levels
 */

struct nest_data {
	unsigned int n_enter;   /* num coroutines entered */
	unsigned int n_return;  /* num coroutines returned */
	unsigned int max;       /* maximum level of nesting */
};

static void nest(void *opaque)
{
	struct nest_data *nd = opaque;

	nd->n_enter++;

	if (nd->n_enter < nd->max) {
		struct coroutine *child;

		child = coroutine_create(nest);
		coroutine_enter(child, nd);
	}

	nd->n_return++;
}

static void test_nesting(void)
{
	struct coroutine *root;
	struct nest_data nd = {
		.n_enter  = 0,
		.n_return = 0,
		.max      = 128,
	};

	root = coroutine_create(nest);
	coroutine_enter(root, &nd);

	/* Must enter and return from max nesting level */
	g_assert_cmpint(nd.n_enter, ==, nd.max);
	g_assert_cmpint(nd.n_return, ==, nd.max);
}

/*
 * Check that yield/enter transfer control correctly
 */

static void yield_5_times(void *opaque)
{
	int *done = opaque;
	int i;

	for (i = 0; i < 5; i++)
		coroutine_yield();

	*done = 1;
}

static void test_yield(void)
{
	struct coroutine *coroutine;
	int done = 0;
	int i = -1; /* one extra time to return from coroutine */

	coroutine = coroutine_create(yield_5_times);
	while (!done) {
		coroutine_enter(coroutine, &done);
		i++;
	}
	g_assert_cmpint(i, ==, 5); /* coroutine must yield 5 times */
}

/*
 * Check that creation, enter, and return work
 */

static void set_and_exit(void *opaque)
{
	int *done = opaque;

	*done = 1;
}

static void test_lifecycle(void)
{
	struct coroutine *coroutine;
	int done = 0;

	/* Create, enter, and return from coroutine */
	coroutine = coroutine_create(set_and_exit);
	coroutine_enter(coroutine, &done);
	g_assert(done); /* expect done to be true (first time) */

	/* Repeat to check that no state affects this test */
	done = 0;
	coroutine = coroutine_create(set_and_exit);
	coroutine_enter(coroutine, &done);
	g_assert(done); /* expect done to be true (second time) */
}

/*
 * Lifecycle benchmark
 */

static void empty_coroutine(void *opaque)
{
	/* Do nothing */
}

static void perf_lifecycle(void)
{
	struct coroutine *coroutine;
	unsigned int i, max;
	double duration;

	max = 1000000;

	g_test_timer_start();
	for (i = 0; i < max; i++) {
		coroutine = coroutine_create(empty_coroutine);
		coroutine_enter(coroutine, NULL);
	}
	duration = g_test_timer_elapsed();

	g_test_message("Lifecycle %u iterations: %f s\n", max, duration);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/coroutine/lifecycle", test_lifecycle);
	g_test_add_func("/coroutine/yield", test_yield);
	g_test_add_func("/coroutine/nesting", test_nesting);
	g_test_add_func("/coroutine/self", test_self);
	g_test_add_func("/coroutine/in_coroutine", test_in_coroutine);
	if (g_test_perf())
		g_test_add_func("/perf/lifecycle", perf_lifecycle);

	return g_test_run();
}
