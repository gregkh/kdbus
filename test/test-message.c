#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

int kdbus_test_message_basic(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	uint64_t cookie = 0x1234abcd5678eeff;
	struct pollfd fd;
	struct kdbus_cmd_recv recv = {};
	int ret;

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	ret = kdbus_add_match_empty(conn);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(env->conn);
	ASSERT_RETURN(ret == 0);

	/* send over 1st connection */
	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* ... and receive on the 2nd */
	fd.fd = conn->fd;
	fd.events = POLLIN | POLLPRI | POLLHUP;
	fd.revents = 0;

	ret = poll(&fd, 1, 100);
	ASSERT_RETURN(ret > 0 && (fd.revents & POLLIN));

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	msg = (struct kdbus_msg *)(conn->buf + recv.offset);
	ASSERT_RETURN(msg->cookie == cookie);

	ret = kdbus_free(conn, recv.offset);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);

	return TEST_OK;
}

static int msg_recv_prio(struct kdbus_conn *conn, int64_t priority)
{
	struct kdbus_cmd_recv recv = {
		.flags = KDBUS_RECV_USE_PRIORITY,
		.priority = priority,
	};
	struct kdbus_msg *msg;
	int ret;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	if (ret < 0) {
		kdbus_printf("error receiving message: %d (%m)\n", -errno);
		return -errno;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.offset);
	kdbus_msg_dump(conn, msg);

	if (msg->priority > priority) {
		kdbus_printf("expected message prio %lld, got %lld\n",
			     (unsigned long long) priority,
			     (unsigned long long) msg->priority);
		return -EINVAL;
	}

	ret = kdbus_free(conn, recv.offset);
	if (ret < 0)
		return ret;

	return 0;
}

int kdbus_test_message_prio(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_a, *conn_b;
	uint64_t cookie = 0;

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,   25, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0, -600, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,   10, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,  -35, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0, -100, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,   20, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,  -15, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0, -800, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0, -150, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0, -150, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,   10, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0, -800, conn_a->id);
	kdbus_msg_send(conn_b, NULL, ++cookie, 0, 0,  -10, conn_a->id);

	kdbus_printf("--- get priority -200\n");
	ASSERT_RETURN(msg_recv_prio(conn_a, -200) == 0);

	kdbus_printf("--- get priority -100\n");
	ASSERT_RETURN(msg_recv_prio(conn_a, -100) == 0);

	kdbus_printf("--- get priority 10\n");
	ASSERT_RETURN(msg_recv_prio(conn_a, 10) == 0);

	kdbus_printf("--- get priority (all)\n");
	ASSERT_RETURN(kdbus_msg_recv(conn_a, NULL) == 0);

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return TEST_OK;
}
