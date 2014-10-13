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
#include <signal.h>
#include <sys/wait.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static struct kdbus_conn *conn_a, *conn_b;
static unsigned int cookie = 0xdeadbeef;

static void nop_handler(int sig) {}

static int interrupt_sync(struct kdbus_conn *conn_src,
			  struct kdbus_conn *conn_dst,
			  int sa_flags)
{
	pid_t pid;
	int ret, status;
	struct kdbus_msg *msg = NULL;
	struct sigaction sa = {
		.sa_handler = nop_handler,
		.sa_flags = sa_flags,
	};

	cookie++;
	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, pid);

	if (pid == 0) {
		ret = sigaction(SIGINT, &sa, NULL);
		ASSERT_RETURN(ret == 0);

		ret = kdbus_msg_send(conn_dst, NULL, cookie,
				     KDBUS_MSG_FLAGS_EXPECT_REPLY |
				     KDBUS_MSG_FLAGS_SYNC_REPLY,
				     5000000000ULL, 0, conn_src->id);
		ASSERT_EXIT(ret == -EINTR);

		_exit(EXIT_SUCCESS);
	}

	ret = kdbus_msg_recv_poll(conn_src, 100, &msg, NULL);
	ASSERT_RETURN(ret == 0 && msg->cookie == cookie);

	kdbus_msg_free(msg);

	ret = kill(pid, SIGINT);
	ASSERT_RETURN_VAL(ret == 0, ret);

	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN_VAL(ret >= 0, ret);

	if (WIFSIGNALED(status))
		return TEST_ERR;

	if (sa_flags | SA_RESTART) {
		/*
		 * Our SYNC logic do not support SA_RESTART flag, so we
		 * don't receive the same packet again. We fail with
		 * ETIMEDOUT.
		 *
		 * For more information, please check "man 7 signal".
		 */
		ret = kdbus_msg_recv_poll(conn_src, 100, NULL, NULL);
		ASSERT_RETURN(ret == -ETIMEDOUT);
	}

	return (status == EXIT_SUCCESS) ? TEST_OK : TEST_ERR;
}

static void *run_thread_reply(void *data)
{
	int ret;

	ret = kdbus_msg_recv_poll(conn_a, 3000, NULL, NULL);
	if (ret == 0) {
		kdbus_printf("Thread received message, sending reply ...\n");
		kdbus_msg_send(conn_a, NULL, 0, 0, cookie, 0, conn_b->id);
	}

	pthread_exit(NULL);
	return NULL;
}

int kdbus_test_sync_reply(struct kdbus_test_env *env)
{
	pthread_t thread;
	int ret;

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	pthread_create(&thread, NULL, run_thread_reply, NULL);

	ret = kdbus_msg_send(conn_b, NULL, cookie,
			     KDBUS_MSG_FLAGS_EXPECT_REPLY |
			     KDBUS_MSG_FLAGS_SYNC_REPLY,
			     5000000000ULL, 0, conn_a->id);

	pthread_join(thread, NULL);
	ASSERT_RETURN(ret == 0);

	ret = interrupt_sync(conn_a, conn_b, SA_NOCLDSTOP);
	ASSERT_RETURN(ret == 0);

	ret = interrupt_sync(conn_a, conn_b, SA_NOCLDSTOP|SA_RESTART);
	ASSERT_RETURN(ret == 0);

	kdbus_printf("-- closing bus connections\n");

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return TEST_OK;
}

#define BYEBYE_ME ((void*)0L)
#define BYEBYE_THEM ((void*)1L)

static void *run_thread_byebye(void *data)
{
	int ret;

	ret = kdbus_msg_recv_poll(conn_a, 3000, NULL, NULL);
	if (ret == 0) {
		kdbus_printf("Thread received message, invoking BYEBYE ...\n");
		kdbus_msg_recv(conn_a, NULL, NULL);
		if (data == BYEBYE_ME)
			ioctl(conn_b->fd, KDBUS_CMD_BYEBYE, 0);
		else if (data == BYEBYE_THEM)
			ioctl(conn_a->fd, KDBUS_CMD_BYEBYE, 0);
	}

	pthread_exit(NULL);
	return NULL;
}

int kdbus_test_sync_byebye(struct kdbus_test_env *env)
{
	pthread_t thread;
	int ret;

	/*
	 * This sends a synchronous message to a thread, which waits until it
	 * received the message and then invokes BYEBYE on the *ORIGINAL*
	 * connection. That is, on the same connection that synchronously waits
	 * for an reply.
	 * This should properly wake the connection up and cause ECONNRESET as
	 * the connection is disconnected now.
	 *
	 * The second time, we do the same but invoke BYEBYE on the *TARGET*
	 * connection. This should also wake up the synchronous sender as the
	 * reply cannot be sent by a disconnected target.
	 */

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	pthread_create(&thread, NULL, run_thread_byebye, BYEBYE_ME);

	ret = kdbus_msg_send(conn_b, NULL, cookie,
			     KDBUS_MSG_FLAGS_EXPECT_REPLY |
			     KDBUS_MSG_FLAGS_SYNC_REPLY,
			     5000000000ULL, 0, conn_a->id);

	ASSERT_RETURN(ret == -ECONNRESET);

	pthread_join(thread, NULL);

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	pthread_create(&thread, NULL, run_thread_byebye, BYEBYE_THEM);

	ret = kdbus_msg_send(conn_b, NULL, cookie,
			     KDBUS_MSG_FLAGS_EXPECT_REPLY |
			     KDBUS_MSG_FLAGS_SYNC_REPLY,
			     5000000000ULL, 0, conn_a->id);

	ASSERT_RETURN(ret == -EPIPE);

	pthread_join(thread, NULL);

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return TEST_OK;
}
