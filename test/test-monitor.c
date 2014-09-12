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
#include <poll.h>
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
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_msg *msg;
	size_t size;
	char *name;
	int ret;

	monitor = kdbus_hello(env->buspath, KDBUS_HELLO_MONITOR, NULL, 0);
	ASSERT_RETURN(monitor);

	/* taking a name must fail */
	name = "foo.bla.blaz";
	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = 0;

	/* check that we can acquire a name */
	ret = ioctl(monitor->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == -1 && errno == EOPNOTSUPP);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_msg_send(env->conn, NULL, cookie, 0, 0,  0, conn->id);
	ASSERT_RETURN(ret == 0);

	/* the recipient should have got the message */
	ret = kdbus_msg_recv(conn, &msg);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	/* and so should the monitor */
	ret = kdbus_msg_recv(monitor, &msg);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_conn_free(monitor);
	kdbus_conn_free(conn);

	return TEST_OK;
}
