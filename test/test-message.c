#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

/* maximum number of queued messages from the same indvidual user */
#define KDBUS_CONN_MAX_MSGS_PER_USER            16

/* maximum number of queued messages in a connection */
#define KDBUS_CONN_MAX_MSGS			256

int kdbus_test_message_basic(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	uint64_t cookie = 0x1234abcd5678eeff;
	uint64_t offset;
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
	ret = kdbus_msg_recv_poll(conn, 100, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_msg_free(msg);

	ret = kdbus_free(conn, offset);
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

/* Return the number of message successfully sent */
static int kdbus_fill_conn_queue(struct kdbus_conn *conn_src,
				 struct kdbus_conn *conn_dst,
				 unsigned int max_msgs)
{
	unsigned int i;
	uint64_t cookie = 0;
	int ret;

	for (i = 0; i < max_msgs; i++) {
		ret = kdbus_msg_send(conn_src, NULL, ++cookie, 0,
				     0, 0, conn_dst->id);
		if (ret < 0)
			break;
	}

	return i;
}


static int kdbus_test_multi_users_quota(struct kdbus_test_env *env)
{
	int ret, efd1, efd2;
	unsigned int cnt, recved_count;
	unsigned int max_user_msgs = KDBUS_CONN_MAX_MSGS_PER_USER;
	struct kdbus_conn *conn;
	struct kdbus_conn *privileged;
	struct kdbus_conn *holder;
	eventfd_t child1_count = 0, child2_count = 0;
	struct kdbus_policy_access access = {
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = geteuid(),
		.access = KDBUS_POLICY_TALK,
	};

	holder = kdbus_hello_registrar(env->buspath, "com.example.a",
				       &access, 1,
				       KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(holder);

	privileged = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(privileged);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	/* Acquire name with access world so they can talk to us */
	ret = kdbus_name_acquire(conn, "com.example.a", NULL);
	ASSERT_EXIT(ret >= 0);

	/* Use this to tell parent how many messages have bee sent */
	efd1 = eventfd(0, EFD_CLOEXEC);
	ASSERT_RETURN_VAL(efd1 >= 0, efd1);

	efd2 = eventfd(0, EFD_CLOEXEC);
	ASSERT_RETURN_VAL(efd2 >= 0, efd2);

	/*
	 * Queue multiple messages as different users at the
	 * same time.
	 *
	 * When the receiver queue count is below
	 * KDBUS_CONN_MAX_MSGS_PER_USER messages are not accounted.
	 *
	 * So we start two threads running under different uid, they
	 * race and each one will try to send:
	 * (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1  msg
	 *
	 * Both threads will return how many message was successfull
	 * queued, later we compute and try to validate the user quota
	 * checks.
	 */
	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_GID, ({
		struct kdbus_conn *unpriv;

		unpriv = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_EXIT(unpriv);

		cnt = kdbus_fill_conn_queue(unpriv, conn,
					    (max_user_msgs * 2) + 1);
		/* Explicitly check for 0 we can't send it to eventfd */
		ASSERT_EXIT(cnt > 0);

		ret = eventfd_write(efd1, cnt);
		ASSERT_EXIT(ret == 0);
	}),
	({;
		/* Queue other messages as a different user */
		ret = RUN_UNPRIVILEGED(UNPRIV_UID - 1, UNPRIV_GID - 1, ({
			struct kdbus_conn *unpriv;

			unpriv = kdbus_hello(env->buspath, 0, NULL, 0);
			ASSERT_EXIT(unpriv);

			cnt = kdbus_fill_conn_queue(unpriv, conn,
						    (max_user_msgs * 2) + 1);
			/* Explicitly check for 0 */
			ASSERT_EXIT(cnt > 0);

			ret = eventfd_write(efd2, cnt);
			ASSERT_EXIT(ret == 0);
		}),
		({ 0; }));
		ASSERT_RETURN(ret == 0);

	}));
	ASSERT_RETURN(ret == 0);

	/* Delay reading, so if children die we are not blocked */
	ret = eventfd_read(efd1, &child1_count);
	ASSERT_RETURN(ret >= 0);

	ret = eventfd_read(efd2, &child2_count);
	ASSERT_RETURN(ret >= 0);

	recved_count = child1_count + child2_count;

	/* Validate how many messages have been sent */
	ASSERT_RETURN(recved_count > 0);

	/*
	 * We start accounting after KDBUS_CONN_MAX_MSGS_PER_USER
	 * so now we have a KDBUS_CONN_MAX_MSGS_PER_USER not
	 * accounted, and given we have at least sent
	 * (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1 for the two threads:
	 * recved_count for both treads will for sure exceed that
	 * value.
	 *
	 * 1) Both thread1 msgs + threads2 msgs exceed
	 *    KDBUS_CONN_MAX_MSGS_PER_USER. Accounting is started.
	 * 2) Now both of them will be able to send only his quota
	 *    which is KDBUS_CONN_MAX_MSGS_PER_USER
	 *    (previous sent messages of 1) were not accounted)
	 */
	ASSERT_RETURN(recved_count > (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1)

	/*
	 * A process should never send more than
	 * (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1)
	 */
	ASSERT_RETURN(child1_count < (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1);

	/*
	 * Now both no accounted messages should give us
	 * KDBUS_CONN_MAX_MSGS_PER_USER when the accounting
	 * started.
	 *
	 * child1 non accounted + child2 non accounted =
	 * KDBUS_CONN_MAX_MSGS_PER_USER
	 */
	ASSERT_RETURN(KDBUS_CONN_MAX_MSGS_PER_USER ==
		((child1_count - KDBUS_CONN_MAX_MSGS_PER_USER) +
		 ((recved_count - child1_count) -
		  KDBUS_CONN_MAX_MSGS_PER_USER)));

	/*
	 * A process should never send more than
	 * (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1)
	 */
	ASSERT_RETURN(child2_count < (KDBUS_CONN_MAX_MSGS_PER_USER * 2) + 1);

	/*
	 * Now both no accounted messages should give us
	 * KDBUS_CONN_MAX_MSGS_PER_USER when the accounting
	 * started.
	 *
	 * child1 non accounted + child2 non accounted =
	 * KDBUS_CONN_MAX_MSGS_PER_USER
	 */
	ASSERT_RETURN(KDBUS_CONN_MAX_MSGS_PER_USER ==
		((child2_count - KDBUS_CONN_MAX_MSGS_PER_USER) +
		 ((recved_count - child2_count) -
		  KDBUS_CONN_MAX_MSGS_PER_USER)));

	/* Try to queue up more, but we fail no space in the pool */
	cnt = kdbus_fill_conn_queue(privileged, conn, KDBUS_CONN_MAX_MSGS);
	ASSERT_RETURN(cnt > 0 && cnt < KDBUS_CONN_MAX_MSGS);

	ret = kdbus_msg_send(privileged, NULL, 0xdeadbeef, 0, 0,
			     0, conn->id);
	ASSERT_RETURN(ret == -ENOBUFS);

	close(efd1);
	close(efd2);

	kdbus_conn_free(privileged);
	kdbus_conn_free(holder);
	kdbus_conn_free(conn);

	return 0;
}

int kdbus_test_message_quota(struct kdbus_test_env *env)
{
	struct kdbus_conn *a, *b;
	uint64_t cookie = 0;
	int ret;
	int i;

	if (geteuid() == 0) {
		ret = kdbus_test_multi_users_quota(env);
		ASSERT_RETURN(ret == 0);

		/* Drop to 'nobody' and continue test */
		ret = setresuid(UNPRIV_UID, UNPRIV_UID, UNPRIV_UID);
		ASSERT_RETURN(ret == 0);
	}

	a = kdbus_hello(env->buspath, 0, NULL, 0);
	b = kdbus_hello(env->buspath, 0, NULL, 0);

	ret = kdbus_fill_conn_queue(b, a,
				    KDBUS_CONN_MAX_MSGS_PER_USER * 2);
	ASSERT_RETURN(ret == (KDBUS_CONN_MAX_MSGS_PER_USER * 2));

	ret = kdbus_msg_send(b, NULL, ++cookie, 0, 0, 0, a->id);
	ASSERT_RETURN(ret == -ENOBUFS);

	for (i = 0; i < KDBUS_CONN_MAX_MSGS_PER_USER * 2; ++i) {
		ret = kdbus_msg_recv(a, NULL, NULL);
		ASSERT_RETURN(ret == 0);
	}

	ret = kdbus_fill_conn_queue(b, a,
				    KDBUS_CONN_MAX_MSGS_PER_USER * 2);
	ASSERT_RETURN(ret == (KDBUS_CONN_MAX_MSGS_PER_USER * 2));

	ret = kdbus_msg_send(b, NULL, ++cookie, 0, 0, 0, a->id);
	ASSERT_RETURN(ret == -ENOBUFS);

	kdbus_conn_free(a);
	kdbus_conn_free(b);

	return TEST_OK;
}
