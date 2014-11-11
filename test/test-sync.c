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

static int send_reply(const struct kdbus_conn *conn,
		      uint64_t reply_cookie,
		      uint64_t dst_id)
{
	struct kdbus_msg *msg;
	const char ref1[1024 * 128 + 3] = "0123456789_0";
	struct kdbus_item *item;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	msg = malloc(size);
	if (!msg) {
		ret = -errno;
		kdbus_printf("unable to malloc()!?\n");
		return ret;
	}

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = dst_id;
	msg->cookie_reply = reply_cookie;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	item = msg->items;

	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)&ref1;
	item->vec.size = sizeof(ref1);
	item = KDBUS_ITEM_NEXT(item);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	free(msg);

	return 0;
}

static int interrupt_sync(struct kdbus_conn *conn_src,
			  struct kdbus_conn *conn_dst)
{
	pid_t pid;
	int ret, status;
	struct kdbus_msg *msg = NULL;
	struct sigaction sa = {
		.sa_handler = nop_handler,
		.sa_flags = SA_NOCLDSTOP|SA_RESTART,
	};

	cookie++;
	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, pid);

	if (pid == 0) {
		ret = sigaction(SIGINT, &sa, NULL);
		ASSERT_EXIT(ret == 0);

		ret = kdbus_msg_send(conn_dst, NULL, cookie,
				     KDBUS_MSG_FLAGS_EXPECT_REPLY |
				     KDBUS_MSG_FLAGS_SYNC_REPLY,
				     100000000ULL, 0, conn_src->id);
		ASSERT_EXIT(ret == -ETIMEDOUT);

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

	ret = kdbus_msg_recv_poll(conn_src, 100, NULL, NULL);
	ASSERT_RETURN(ret == -ETIMEDOUT);

	return (status == EXIT_SUCCESS) ? TEST_OK : TEST_ERR;
}

static void *run_thread_reply(void *data)
{
	int ret;

	ret = kdbus_msg_recv_poll(conn_a, 3000, NULL, NULL);
	if (ret == 0) {
		kdbus_printf("Thread received message, sending reply ...\n");
		send_reply(conn_a, cookie, conn_b->id);
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

	ret = interrupt_sync(conn_a, conn_b);
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
