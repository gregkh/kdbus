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
#include <sys/mman.h>
#include <stdbool.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

static int test_bus_creator_info(const char *bus_path)
{
	int ret;
	struct kdbus_conn *conn;
	struct kdbus_cmd_info cmd = {};

	cmd.size = sizeof(cmd);

	conn = kdbus_hello(bus_path, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = ioctl(conn->fd, KDBUS_CMD_BUS_CREATOR_INFO, &cmd);
	ASSERT_RETURN_VAL(ret == 0, ret);

	ret = kdbus_free(conn, cmd.offset);
	ASSERT_RETURN_VAL(ret == 0, ret);

	return 0;
}

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
	int ret, control_fd2;
	uid_t uid;

	snprintf(s, sizeof(s), "%s/control", env->root);
	env->control_fd = open(s, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(env->control_fd >= 0);

	control_fd2 = open(s, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(control_fd2 >= 0);

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

	ret = ioctl(control_fd2, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == -1 && errno == EEXIST);

	snprintf(s, sizeof(s), "%s/%u-blah-1/bus", env->root, uid);
	ASSERT_RETURN(access(s, F_OK) == 0);

	ret = test_bus_creator_info(s);
	ASSERT_RETURN(ret == 0);

	/* can't use the same fd for bus make twice */
	ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
	ASSERT_RETURN(ret == -1 && errno == EBADFD);

	close(control_fd2);

	return TEST_OK;
}
