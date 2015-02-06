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
#include <sys/mman.h>
#include <stdbool.h>

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

static struct kdbus_item *kdbus_get_item(struct kdbus_info *info,
					 uint64_t type)
{
	struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, info, items)
		if (item->type == type)
			return item;

	return NULL;
}

static int test_bus_creator_info(const char *bus_path)
{
	int ret;
	uint64_t offset;
	struct kdbus_conn *conn;
	struct kdbus_info *info;
	struct kdbus_item *item;
	char *tmp, *busname;

	/* extract the bus-name from @bus_path */
	tmp = strdup(bus_path);
	ASSERT_RETURN(tmp);
	busname = strrchr(tmp, '/');
	ASSERT_RETURN(busname);
	*busname = 0;
	busname = strrchr(tmp, '/');
	ASSERT_RETURN(busname);
	++busname;

	conn = kdbus_hello(bus_path, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_bus_creator_info(conn, _KDBUS_ATTACH_ALL, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(conn->buf + offset);

	item = kdbus_get_item(info, KDBUS_ITEM_MAKE_NAME);
	ASSERT_RETURN(item);
	ASSERT_RETURN(!strcmp(item->str, busname));

	ret = kdbus_free(conn, offset);
	ASSERT_RETURN_VAL(ret == 0, ret);

	free(tmp);
	kdbus_conn_free(conn);
	return 0;
}

int kdbus_test_bus_make(struct kdbus_test_env *env)
{
	struct {
		struct kdbus_cmd cmd;

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
	char s[PATH_MAX], *name;
	int ret, control_fd2;
	uid_t uid;

	name = unique_name("");
	ASSERT_RETURN(name);

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
	bus_make.cmd.size = sizeof(struct kdbus_cmd) +
			    sizeof(bus_make.bs) + bus_make.n_size;
	ret = kdbus_cmd_bus_make(env->control_fd, &bus_make.cmd);
	ASSERT_RETURN(ret == -EINVAL);

	/* non alphanumeric character */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-blah@123", uid);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.cmd.size = sizeof(struct kdbus_cmd) +
			    sizeof(bus_make.bs) + bus_make.n_size;
	ret = kdbus_cmd_bus_make(env->control_fd, &bus_make.cmd);
	ASSERT_RETURN(ret == -EINVAL);

	/* '-' at the end */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-blah-", uid);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.cmd.size = sizeof(struct kdbus_cmd) +
			    sizeof(bus_make.bs) + bus_make.n_size;
	ret = kdbus_cmd_bus_make(env->control_fd, &bus_make.cmd);
	ASSERT_RETURN(ret == -EINVAL);

	/* create a new bus */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-%s-1", uid, name);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.cmd.size = sizeof(struct kdbus_cmd) +
			    sizeof(bus_make.bs) + bus_make.n_size;
	ret = kdbus_cmd_bus_make(env->control_fd, &bus_make.cmd);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_cmd_bus_make(control_fd2, &bus_make.cmd);
	ASSERT_RETURN(ret == -EEXIST);

	snprintf(s, sizeof(s), "%s/%u-%s-1/bus", env->root, uid, name);
	ASSERT_RETURN(access(s, F_OK) == 0);

	ret = test_bus_creator_info(s);
	ASSERT_RETURN(ret == 0);

	/* can't use the same fd for bus make twice, even though a different
	 * bus name is used
	 */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-%s-2", uid, name);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.cmd.size = sizeof(struct kdbus_cmd) +
			    sizeof(bus_make.bs) + bus_make.n_size;
	ret = kdbus_cmd_bus_make(env->control_fd, &bus_make.cmd);
	ASSERT_RETURN(ret == -EBADFD);

	/* create a new bus, with different fd and different bus name */
	snprintf(bus_make.name, sizeof(bus_make.name), "%u-%s-2", uid, name);
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;
	bus_make.cmd.size = sizeof(struct kdbus_cmd) +
			    sizeof(bus_make.bs) + bus_make.n_size;
	ret = kdbus_cmd_bus_make(control_fd2, &bus_make.cmd);
	ASSERT_RETURN(ret == 0);

	close(control_fd2);
	free(name);

	return TEST_OK;
}
