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
#include <poll.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdbool.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static struct kdbus_conn *conn_a, *conn_b;
static unsigned int cookie = 0xdeadbeef;

static void *run_thread(void *data)
{
	struct pollfd fd;
	int ret;

	fd.fd = conn_a->fd;
	fd.events = POLLIN | POLLPRI | POLLHUP;
	fd.revents = 0;

	ret = poll(&fd, 1, 3000);
	if (ret <= 0)
		goto thread_exit;

	if (fd.revents & POLLIN) {
		kdbus_printf("Thread received message, sending reply ...\n");
		kdbus_msg_recv(conn_a, NULL);
		kdbus_msg_send(conn_a, NULL, 0, 0, cookie, 0, conn_b->id);
	}

thread_exit:
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

	pthread_create(&thread, NULL, run_thread, NULL);

	ret = kdbus_msg_send(conn_b, NULL, cookie,
			     KDBUS_MSG_FLAGS_EXPECT_REPLY |
			     KDBUS_MSG_FLAGS_SYNC_REPLY,
			     5000000000ULL, 0, conn_a->id);

	pthread_join(thread, NULL);
	ASSERT_RETURN(ret == 0);

	kdbus_printf("-- closing bus connections\n");
	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return TEST_OK;
}
