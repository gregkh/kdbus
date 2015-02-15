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
#include <sys/mman.h>
#include <sys/capability.h>
#include <sys/wait.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

int kdbus_test_monitor(struct kdbus_test_env *env)
{
	struct kdbus_conn *monitor, *conn;
	unsigned int cookie = 0xdeadbeef;
	struct kdbus_msg *msg;
	uint64_t offset = 0;
	int ret;

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	/* add matches to make sure the monitor do not trigger an item add or
	 * remove on connect and disconnect, respectively.
	 */
	ret = kdbus_add_match_id(conn, 0x1, KDBUS_ITEM_ID_ADD,
				 KDBUS_MATCH_ID_ANY);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_id(conn, 0x2, KDBUS_ITEM_ID_REMOVE,
				 KDBUS_MATCH_ID_ANY);
	ASSERT_RETURN(ret == 0);

	/* register a monitor */
	monitor = kdbus_hello(env->buspath, KDBUS_HELLO_MONITOR, NULL, 0);
	ASSERT_RETURN(monitor);

	/* make sure we did not receive a monitor connect notification */
	ret = kdbus_msg_recv(conn, &msg, &offset);
	ASSERT_RETURN(ret == -EAGAIN);

	/* check that a monitor cannot acquire a name */
	ret = kdbus_name_acquire(monitor, "foo.bar.baz", NULL);
	ASSERT_RETURN(ret == -EOPNOTSUPP);

	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0,  0, conn->id);
	ASSERT_RETURN(ret == 0);

	/* the recipient should have gotten the message */
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

	/* Installing matches for monitors must fais must fail */
	ret = kdbus_add_match_empty(monitor);
	ASSERT_RETURN(ret == -EOPNOTSUPP);

	cookie++;
	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* The monitor should get the message. */
	ret = kdbus_msg_recv_poll(monitor, 100, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_msg_free(msg);
	kdbus_free(monitor, offset);

	/*
	 * Since we are the only monitor, update the attach flags
	 * and tell we are not interessted in attach flags recv
	 */

	ret = kdbus_conn_update_attach_flags(monitor,
					     _KDBUS_ATTACH_ALL,
					     0);
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
					     _KDBUS_ATTACH_ALL,
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
	/* make sure we did not receive a monitor disconnect notification */
	ret = kdbus_msg_recv(conn, &msg, &offset);
	ASSERT_RETURN(ret == -EAGAIN);

	kdbus_conn_free(conn);

	/* Make sure that monitor as unprivileged is not allowed */
	ret = test_is_capable(CAP_SETUID, CAP_SETGID, -1);
	ASSERT_RETURN(ret >= 0);

	if (ret && all_uids_gids_are_mapped()) {
		ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_UID, ({
			monitor = kdbus_hello(env->buspath,
					      KDBUS_HELLO_MONITOR,
					      NULL, 0);
			ASSERT_EXIT(!monitor && errno == EPERM);

			_exit(EXIT_SUCCESS);
		}),
		({ 0; }));
		ASSERT_RETURN(ret == 0);
	}

	return TEST_OK;
}
