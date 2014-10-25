#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

static bool kdbus_item_in_message(struct kdbus_msg *msg,
				  uint64_t type)
{
	const struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == type)
			return true;

	return false;
}

int kdbus_test_monitor(struct kdbus_test_env *env)
{
	struct kdbus_conn *monitor, *conn;
	unsigned int cookie = 0xdeadbeef;
	struct kdbus_msg *msg;
	uint64_t offset = 0;
	int ret;

	monitor = kdbus_hello(env->buspath, KDBUS_HELLO_MONITOR, NULL, 0);
	ASSERT_RETURN(monitor);

	/* check that we can acquire a name */
	ret = kdbus_name_acquire(monitor, "foo.bar.baz", NULL);
	ASSERT_RETURN(ret == -EOPNOTSUPP);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0,  0, conn->id);
	ASSERT_RETURN(ret == 0);

	/* the recipient should have got the message */
	ret = kdbus_msg_recv(conn, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);
	kdbus_msg_free(msg);
	kdbus_free(conn, offset);

	/* and so should the monitor */
	ret = kdbus_msg_recv(monitor, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_msg_free(msg);
	kdbus_free(monitor, offset);

	cookie++;
	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* The monitor did not install matches, this will timeout */
	ret = kdbus_msg_recv_poll(monitor, 100, NULL, NULL);
	ASSERT_RETURN(ret == -ETIMEDOUT);

	/* Install empty match for monitor */
	ret = kdbus_add_match_empty(monitor);
	ASSERT_RETURN(ret == 0);

	cookie++;
	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* The monitor should get the message now. */
	ret = kdbus_msg_recv_poll(monitor, 100, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_msg_free(msg);
	kdbus_free(monitor, offset);

	/*
	 * Since we are the only monitor, update the attach flags
	 * and tell we are not interessted in attach flags
	*/

	ret = kdbus_conn_update_attach_flags(monitor, 0);
	ASSERT_RETURN(ret == 0);

	cookie++;
	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv_poll(monitor, 100, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	ret = kdbus_item_in_message(msg, KDBUS_ITEM_TIMESTAMP);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);
	kdbus_free(monitor, offset);

	/*
	 * Now we are interested in KDBUS_ITEM_TIMESTAMP and
	 * KDBUS_ITEM_CREDS
	 */
	ret = kdbus_conn_update_attach_flags(monitor,
					     KDBUS_ATTACH_TIMESTAMP |
					     KDBUS_ATTACH_CREDS);
	ASSERT_RETURN(ret == 0);

	cookie++;
	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv_poll(monitor, 100, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	ret = kdbus_item_in_message(msg, KDBUS_ITEM_TIMESTAMP);
	ASSERT_RETURN(ret == 1);

	ret = kdbus_item_in_message(msg, KDBUS_ITEM_CREDS);
	ASSERT_RETURN(ret == 1);

	/* the KDBUS_ITEM_PID_COMM was not requested */
	ret = kdbus_item_in_message(msg, KDBUS_ITEM_PID_COMM);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);
	kdbus_free(monitor, offset);

	kdbus_conn_free(monitor);
	kdbus_conn_free(conn);

	return TEST_OK;
}
