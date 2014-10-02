#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdbool.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

struct race_thread {
	pthread_spinlock_t lock;
	pthread_t thread;
	int (*fn) (struct kdbus_test_env *env, void *ctx);
	struct kdbus_test_env *env;
	void *ctx;
	int ret;
};

static void *race_thread_fn(void *data)
{
	struct race_thread *thread = data;
	int ret;

	ret = pthread_spin_lock(&thread->lock);
	if (ret < 0)
		goto error;

	ret = thread->fn(thread->env, thread->ctx);
	pthread_spin_unlock(&thread->lock);

error:
	return (void*)(long)ret;
}

static int race_thread_init(struct race_thread *thread)
{
	int ret;

	ret = pthread_spin_init(&thread->lock, PTHREAD_PROCESS_PRIVATE);
	ASSERT_RETURN(ret >= 0);

	ret = pthread_spin_lock(&thread->lock);
	ASSERT_RETURN(ret >= 0);

	ret = pthread_create(&thread->thread, NULL, race_thread_fn, thread);
	ASSERT_RETURN(ret >= 0);

	return TEST_OK;
}

static void race_thread_run(struct race_thread *thread,
			    int (*fn)(struct kdbus_test_env *env, void *ctx),
			    struct kdbus_test_env *env, void *ctx)
{
	int ret;

	thread->fn = fn;
	thread->env = env;
	thread->ctx = ctx;

	ret = pthread_spin_unlock(&thread->lock);
	if (ret < 0)
		abort();
}

static int race_thread_join(struct race_thread *thread)
{
	void *val = (void*)(long)-EFAULT;
	int ret;

	ret = pthread_join(thread->thread, &val);
	ASSERT_RETURN(ret >= 0);

	thread->ret = (long)val;

	return TEST_OK;
}

static void shuffle(size_t *array, size_t n)
{
	size_t i, j, t;

	if (n <= 1)
		return;

	for (i = 0; i < n - 1; i++) {
		j = i + rand() / (RAND_MAX / (n - i) + 1);
		t = array[j];
		array[j] = array[i];
		array[i] = t;
	}
}

static int race_thread(int (*init_fn) (struct kdbus_test_env *env, void *ctx),
		       int (*exit_fn) (struct kdbus_test_env *env, void *ctx,
		                       int *ret, size_t n_ret),
		       int (*verify_fn) (struct kdbus_test_env *env, void *ctx),
		       int (**fns) (struct kdbus_test_env *env, void *ctx),
		       size_t n_fns, struct kdbus_test_env *env, void *ctx,
		       size_t runs)
{
	struct race_thread *t;
	size_t i, num, *order;
	int *ret, r;

	t = calloc(sizeof(*t), n_fns);
	ASSERT_RETURN(t != NULL);

	ret = calloc(sizeof(*ret), n_fns);
	ASSERT_RETURN(ret != NULL);

	order = calloc(sizeof(*order), n_fns);
	ASSERT_RETURN(order != NULL);

	for (num = 0; num < runs; ++num) {
		ASSERT_RETURN(init_fn(env, ctx) == TEST_OK);

		for (i = 0; i < n_fns; ++i) {
			ASSERT_RETURN(race_thread_init(&t[i]) == TEST_OK);
			order[i] = i;
		}

		/* random order */
		shuffle(order, n_fns);
		for (i = 0; i < n_fns; ++i)
			race_thread_run(&t[order[i]], fns[order[i]], env, ctx);

		for (i = 0; i < n_fns; ++i) {
			ASSERT_RETURN(race_thread_join(&t[i]) == TEST_OK);
			ret[i] = t[i].ret;
		}

		ASSERT_RETURN(exit_fn(env, ctx, ret, n_fns) == TEST_OK);
	}

	r = verify_fn(env, ctx);
	free(order);
	free(ret);
	free(t);
	return r;
}

#define ASSERT_RACE(env, ctx, runs, init_fn, exit_fn, verify_fn, ...) ({\
		int (*fns[])(struct kdbus_test_env*, void*) = {		\
			__VA_ARGS__					\
		};							\
		size_t cnt = sizeof(fns) / sizeof(*fns);		\
		race_thread(init_fn, exit_fn, verify_fn,		\
				fns, cnt, env, ctx, runs);		\
	})

#define TEST_RACE2(_name_, _runs_, _ctx_, _a_, _b_, _init_, _exit_, _verify_)\
	static int _name_ ## ___a(struct kdbus_test_env *env, void *_ctx)\
	{								\
		__attribute__((__unused__)) _ctx_ *ctx = _ctx;		\
		_a_;							\
		return TEST_OK;						\
	}								\
	static int _name_ ## ___b(struct kdbus_test_env *env, void *_ctx)\
	{								\
		__attribute__((__unused__)) _ctx_ *ctx = _ctx;		\
		_b_;							\
		return TEST_OK;						\
	}								\
	static int _name_ ## ___init(struct kdbus_test_env *env,	\
				void *_ctx)				\
	{								\
		__attribute__((__unused__)) _ctx_ *ctx = _ctx;		\
		_init_;							\
		return TEST_OK;						\
	}								\
	static int _name_ ## ___exit(struct kdbus_test_env *env,	\
				void *_ctx, int *ret, size_t n_ret)	\
	{								\
		__attribute__((__unused__)) _ctx_ *ctx = _ctx;		\
		_exit_;							\
		return TEST_OK;						\
	}								\
	static int _name_ ## ___verify(struct kdbus_test_env *env,	\
				void *_ctx)				\
	{								\
		__attribute__((__unused__)) _ctx_ *ctx = _ctx;		\
		_verify_;						\
		return TEST_OK;						\
	}								\
	int _name_ (struct kdbus_test_env *env) {			\
		_ctx_ ctx;						\
		memset(&ctx, 0, sizeof(ctx));				\
		return ASSERT_RACE(env, &ctx, _runs_,			\
				_name_ ## ___init,			\
				_name_ ## ___exit,			\
				_name_ ## ___verify,			\
				_name_ ## ___a,				\
				_name_ ## ___b);			\
	}

/*
 * Race Testing
 * This file provides some rather trivial helpers to run multiple threads in
 * parallel and test for races. You can define races with TEST_RACEX(), whereas
 * 'X' is the number of threads you want. The arguments to this function should
 * be code-blocks that are executed in the threads. Each code-block, if it
 * does not contain a "return" statement, will implicitly return TEST_OK.
 *
 * The arguments are:
 * @arg1: The name of the test to define
 * @arg2: The number of runs
 * @arg3: The datatype used as context across all test runs
 * @arg4-@argN: The code-blocks for the threads to run.
 * @argN+1: The code-block that is run before each test-run. Use it to
 *          initialize your contexts.
 * @argN+2: The code-block that is run after each test-run. Use it to verify
 *          everything went as expected.
 * @argN+3: The code-block that is executed after all runs are finished. Use it
 *          to verify the sum of results.
 *
 * Each function has "env" and "ctx" as variables implicitly defined.
 * Furthermore, the function executed after the tests were run can access "ret",
 * which is an array of return values of all threads. "n_ret" is the number of
 * threads.
 *
 * Race testing is kinda nasty if you cannot place breakpoints yourself.
 * Therefore, we run each thread multiple times and allow you to verify the
 * results of all test-runs after we're finished. Usually, we try to verify all
 * possible outcomes happened. However, no-one can predict how the scheduler
 * ran each thread, even if we run 10k times. Furthermore, the execution of all
 * threads is randomized by us, so we cannot predict how they're run. Therefore,
 * we only return TEST_SKIP in those cases. This is not a hard-failure, but
 * signals test-runners that something went unexpected.
 */

/*
 * We run BYEBYE in parallel in two threads. Only one of them is allowed to
 * succeed, the other one *MUST* return -EALREADY.
 */
TEST_RACE2(kdbus_test_race_byebye, 100, int,
	({
		return ioctl(env->conn->fd, KDBUS_CMD_BYEBYE, 0) ? -errno : 0;
	}),
	({
		return ioctl(env->conn->fd, KDBUS_CMD_BYEBYE, 0) ? -errno : 0;
	}),
	({
		env->conn = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(env->conn);
	}),
	({
		ASSERT_RETURN((ret[0] == 0 && ret[1] == -EALREADY) ||
			      (ret[1] == 0 && ret[0] == -EALREADY));
		kdbus_conn_free(env->conn);
		env->conn = NULL;
	}),
	({
	}))

/*
 * Run BYEBYE against MATCH_REMOVE. If BYEBYE is first, it returns 0 and
 * MATCH_REMOVE must fail with ECONNRESET. If BYEBYE is last, it still succeeds
 * but MATCH_REMOVE does, too.
 * Run 10k times; at least on my machine it takes usually about ~100 runs to
 * trigger ECONNRESET races.
 */
TEST_RACE2(kdbus_test_race_byebye_match, 10000,
	struct {
		bool res1 : 1;
		bool res2 : 1;
	},
	({
		return ioctl(env->conn->fd, KDBUS_CMD_BYEBYE, 0) ? -errno : 0;
	}),
	({
		struct kdbus_cmd_match cmd = { };
		int ret;

		cmd.size = sizeof(cmd);
		cmd.cookie = 0xdeadbeef;
		ret = ioctl(env->conn->fd, KDBUS_CMD_MATCH_REMOVE, &cmd);
		if (ret == 0 || errno == ENOENT)
			return 0;

		return -errno;
	}),
	({
		env->conn = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(env->conn);
	}),
	({
		if (ret[0] == 0 && ret[1] == 0) {
			/* MATCH_REMOVE ran first, then BYEBYE */
			ctx->res1 = true;
		} else if (ret[0] == 0 && ret[1] == -ECONNRESET) {
			/* BYEBYE ran first, then MATCH_REMOVE failed */
			ctx->res2 = true;
		} else {
			ASSERT_RETURN(0);
		}

		kdbus_conn_free(env->conn);
		env->conn = NULL;
	}),
	({
		if (!ctx->res1 || !ctx->res2)
			return TEST_SKIP;
	}))
