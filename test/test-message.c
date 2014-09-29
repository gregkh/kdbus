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

static int msg_recv_prio(struct kdbus_conn *conn,
			 int64_t requested_prio,
			 int64_t expected_prio)
{
	struct kdbus_cmd_recv recv = {
		.flags = KDBUS_RECV_USE_PRIORITY,
		.priority = requested_prio,
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

	if (msg->priority != expected_prio) {
		kdbus_printf("expected message prio %lld, got %lld\n",
			     (unsigned long long) expected_prio,
			     (unsigned long long) msg->priority);
		return -EINVAL;
	}

	kdbus_msg_free(msg);
	ret = kdbus_free(conn, recv.offset);
	if (ret < 0)
		return ret;

	return 0;
}

int kdbus_test_message_prio(struct kdbus_test_env *env)
{
	struct kdbus_conn *a, *b;
	uint64_t cookie = 0;

	a = kdbus_hello(env->buspath, 0, NULL, 0);
	b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(a && b);

	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   25, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -600, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   10, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,  -35, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -100, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   20, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,  -15, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -800, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -150, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   10, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -800, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,  -10, a->id) == 0);

	ASSERT_RETURN(msg_recv_prio(a, -200, -800) == 0);
	ASSERT_RETURN(msg_recv_prio(a, -100, -800) == 0);
	ASSERT_RETURN(msg_recv_prio(a, -400, -600) == 0);
	ASSERT_RETURN(msg_recv_prio(a, -400, -600) == -ENOMSG);
	ASSERT_RETURN(msg_recv_prio(a, 10, -150) == 0);
	ASSERT_RETURN(msg_recv_prio(a, 10, -100) == 0);

	kdbus_printf("--- get priority (all)\n");
	ASSERT_RETURN(kdbus_msg_recv(a, NULL, NULL) == 0);

	kdbus_conn_free(a);
	kdbus_conn_free(b);

	return TEST_OK;
}
