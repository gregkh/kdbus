#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

int kdbus_test_bus_make(struct kdbus_test_env *env)
{
	struct {
		struct kdbus_cmd_make head;

		/* bloom size item */
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_bloom_parameter bloom;
		} bs;

		/* name item */
		uint64_t n_size;
		uint64_t n_type;
		char name[64];
	} bus_make;
	char s[PATH_MAX];
	int ret;
	uid_t uid;

	env->control_fd = open("/dev/" KBUILD_MODNAME "/control",
			       O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(env->control_fd >= 0);

	memset(&bus_make, 0, sizeof(bus_make));

	bus_make.bs.size = sizeof(bus_make.bs);
	bus_make.bs.type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bs.bloom.size = 64;
	bus_make.bs.bloom.n_hash = 1;

	bus_make.n_type = KDBUS_ITEM_MAKE_NAME;

	uid = getuid();

	/* missing uid prefix */
	snprintf(bus_make.name, sizeof(bus_make.name), "foo");
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.head.size = sizeof(struct kdbus_cmd_make) +
			     sizeof(bus_make.bs) + bus_make.n_size;
	ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	/* non alphanumeric character */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-blah@123", uid);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.head.size = sizeof(struct kdbus_cmd_make) +
			     sizeof(bus_make.bs) + bus_make.n_size;
	ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	/* '-' at the end */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-blah-", uid);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.head.size = sizeof(struct kdbus_cmd_make) +
			     sizeof(bus_make.bs) + bus_make.n_size;
	ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	/* create a new bus */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-blah-1", uid);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.head.size = sizeof(struct kdbus_cmd_make) +
			     sizeof(bus_make.bs) + bus_make.n_size;
	ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == 0);
	snprintf(s, sizeof(s), "/dev/" KBUILD_MODNAME "/%u-blah-1/bus", uid);
	ASSERT_RETURN(access(s, F_OK) == 0);

	/* can't use the same fd for bus make twice */
	ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == -1 && errno == EBADFD);

	return TEST_OK;
}

int kdbus_test_hello(struct kdbus_test_env *env)
{
	struct kdbus_cmd_hello hello;
	int fd, ret;

	memset(&hello, 0, sizeof(hello));

	fd = open(env->buspath, O_RDWR|O_CLOEXEC);
	if (fd < 0)
		return TEST_ERR;

	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD;
	hello.attach_flags = _KDBUS_ATTACH_ALL;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;

	/* an unaligned hello must result in -EFAULT */
	ret = ioctl(fd, KDBUS_CMD_HELLO, (char *) &hello + 1);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	/* a size of 0 must return EMSGSIZE */
	hello.size = 1;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	hello.size = sizeof(struct kdbus_cmd_hello);

	/* check faulty flags */
	hello.conn_flags = 1ULL << 32;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EOPNOTSUPP);

	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD;

	/* check for faulty pool sizes */
	hello.pool_size = 0;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	hello.pool_size = 4097;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	hello.pool_size = POOL_SIZE;

	/* success test */
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == 0);

	close(fd);
	fd = open(env->buspath, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(fd >= 0);

	/* no ACTIVATOR flag without a name */
	hello.conn_flags = KDBUS_HELLO_ACTIVATOR;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	return TEST_OK;
}

int kdbus_test_byebye(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct kdbus_cmd_recv recv = {};
	int ret;

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	ret = kdbus_add_match_empty(conn);
	ASSERT_RETURN(ret == 0);

	kdbus_add_match_empty(env->conn);
	ASSERT_RETURN(ret == 0);

	/* send over 1st connection */
	ret = kdbus_msg_send(env->conn, NULL, 0, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* say byebye on the 2nd, which must fail */
	ret = ioctl(conn->fd, KDBUS_CMD_BYEBYE, 0);
	ASSERT_RETURN(ret == -1 && errno == EBUSY);

	/* receive the message */
	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_free(conn, recv.offset);
	ASSERT_RETURN(ret == 0);

	/* and try again */
	ret = ioctl(conn->fd, KDBUS_CMD_BYEBYE, 0);
	ASSERT_RETURN(ret == 0);

	/* a 2nd try should result in -EALREADY */
	ret = ioctl(conn->fd, KDBUS_CMD_BYEBYE, 0);
	ASSERT_RETURN(ret == -1 && errno == EOPNOTSUPP);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_conn_info(struct kdbus_test_env *env)
{
	int ret;
	struct {
		struct kdbus_cmd_conn_info cmd_info;
		char name[64];
	} buf;

	buf.cmd_info.size = sizeof(struct kdbus_cmd_conn_info);
	buf.cmd_info.flags = 0;
	buf.cmd_info.id = env->conn->id;

	ret = ioctl(env->conn->fd, KDBUS_CMD_CONN_INFO, &buf);
	ASSERT_RETURN(ret == 0);

	/* try to pass a name that is longer than the buffer's size */
	strcpy(buf.cmd_info.name, "foo.bar.bla");
	buf.cmd_info.id = 0;
	buf.cmd_info.size = sizeof(struct kdbus_cmd_conn_info) + 10;
	ret = ioctl(env->conn->fd, KDBUS_CMD_CONN_INFO, &buf);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	return TEST_OK;
}

int kdbus_test_conn_update(struct kdbus_test_env *env)
{
	const struct kdbus_item *item;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	int found = 0;
	int ret;

	/*
	 * kdbus_hello() sets all attach flags. Receive a message by this
	 * connection, and make sure a timestamp item (just to pick one) is
	 * present.
	 */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_msg_send(env->conn, NULL, 0x12345678, 0, 0, 0, conn->id);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn, &msg);
	ASSERT_RETURN(ret == 0);

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == KDBUS_ITEM_TIMESTAMP)
			found = 1;

	ASSERT_RETURN(found == 1);

	/*
	 * Now, modify the attach flags and repeat the action. The item must
	 * now be missing.
	 */
	found = 0;

	ret = kdbus_conn_update_attach_flags(conn, _KDBUS_ATTACH_ALL &
						   ~KDBUS_ATTACH_TIMESTAMP);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_send(env->conn, NULL, 0x12345678, 0, 0, 0, conn->id);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn, &msg);
	ASSERT_RETURN(ret == 0);

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == KDBUS_ITEM_TIMESTAMP)
			found = 1;

	ASSERT_RETURN(found == 0);

	kdbus_conn_free(conn);

	return TEST_OK;
}
