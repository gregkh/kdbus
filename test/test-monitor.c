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

	kdbus_conn_free(monitor);
	kdbus_conn_free(conn);

	return TEST_OK;
}
