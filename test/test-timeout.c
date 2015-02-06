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
#include <stdbool.h>

#include "kdbus-api.h"
#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

int timeout_msg_recv(struct kdbus_conn *conn, uint64_t *expected)
{
	struct kdbus_cmd_recv recv = { .size = sizeof(recv) };
	struct kdbus_msg *msg;
	int ret;

	ret = kdbus_cmd_recv(conn->fd, &recv);
	if (ret < 0) {
		kdbus_printf("error receiving message: %d (%m)\n", ret);
		return ret;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.msg.offset);

	ASSERT_RETURN_VAL(msg->payload_type == KDBUS_PAYLOAD_KERNEL, -EINVAL);
	ASSERT_RETURN_VAL(msg->src_id == KDBUS_SRC_ID_KERNEL, -EINVAL);
	ASSERT_RETURN_VAL(msg->dst_id == conn->id, -EINVAL);

	*expected &= ~(1ULL << msg->cookie_reply);
	kdbus_printf("Got message timeout for cookie %llu\n",
		     msg->cookie_reply);

	ret = kdbus_free(conn, recv.msg.offset);
	if (ret < 0)
		return ret;

	return 0;
}

int kdbus_test_timeout(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_a, *conn_b;
	struct pollfd fd;
	int ret, i, n_msgs = 4;
	uint64_t expected = 0;
	uint64_t cookie = 0xdeadbeef;

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	fd.fd = conn_b->fd;

	/*
	 * send messages that expect a reply (within 100 msec),
	 * but never answer it.
	 */
	for (i = 0; i < n_msgs; i++, cookie++) {
		kdbus_printf("Sending message with cookie %llu ...\n",
			     (unsigned long long)cookie);
		ASSERT_RETURN(kdbus_msg_send(conn_b, NULL, cookie,
			      KDBUS_MSG_EXPECT_REPLY,
			      (i + 1) * 100ULL * 1000000ULL, 0,
			      conn_a->id) == 0);
		expected |= 1ULL << cookie;
	}

	for (;;) {
		fd.events = POLLIN | POLLPRI | POLLHUP;
		fd.revents = 0;

		ret = poll(&fd, 1, (n_msgs + 1) * 100);
		if (ret == 0)
			kdbus_printf("--- timeout\n");
		if (ret <= 0)
			break;

		if (fd.revents & POLLIN)
			ASSERT_RETURN(!timeout_msg_recv(conn_b, &expected));

		if (expected == 0)
			break;
	}

	ASSERT_RETURN(expected == 0);

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return TEST_OK;
}
