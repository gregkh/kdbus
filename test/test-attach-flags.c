#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/unistd.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static struct kdbus_conn *__kdbus_hello(const char *path, uint64_t flags,
					uint64_t attach_flags_send,
					uint64_t attach_flags_recv)
{
	int ret, fd;
	struct kdbus_conn *conn;
	struct {
		struct kdbus_cmd_hello hello;

		struct {
			uint64_t size;
			uint64_t type;
			char str[16];
		} conn_name;

		uint8_t extra_items[0];
	} h;

	memset(&h, 0, sizeof(h));

	kdbus_printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		kdbus_printf("--- error %d (%m)\n", fd);
		return NULL;
	}

	h.hello.flags = flags | KDBUS_HELLO_ACCEPT_FD;
	h.hello.attach_flags_send = attach_flags_send;
	h.hello.attach_flags_recv = attach_flags_recv;
	h.conn_name.type = KDBUS_ITEM_CONN_DESCRIPTION;
	strcpy(h.conn_name.str, "this-is-my-name");
	h.conn_name.size = KDBUS_ITEM_HEADER_SIZE + strlen(h.conn_name.str) + 1;

	h.hello.size = sizeof(h);
	h.hello.pool_size = POOL_SIZE;

	ret = ioctl(fd, KDBUS_CMD_HELLO, &h.hello);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("--- error when saying hello: %d (%m)\n", ret);
		return NULL;
	}

	kdbus_printf("-- New connection ID : %llu\n",
		     (unsigned long long)h.hello.id);

	conn = malloc(sizeof(*conn));
	if (!conn) {
		kdbus_printf("unable to malloc()!?\n");
		return NULL;
	}

	conn->buf = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (conn->buf == MAP_FAILED) {
		ret = -errno;
		free(conn);
		close(fd);
		kdbus_printf("--- error mmap: %d (%m)\n", ret);
		return NULL;
	}

	conn->fd = fd;
	conn->id = h.hello.id;
	return conn;
}

static int kdbus_bus_peer_flags(struct kdbus_test_env *env)
{
	int ret;
	int control_fd;
	char *path;
	char *busname;
	char buspath[2048];
	char control_path[2048];
	uint64_t attach_flags_mask;
	struct kdbus_conn *conn;

	snprintf(control_path, sizeof(control_path),
		 "%s/control", env->root);

	/*
	 * Set kdbus system-wide mask to 0, this has nothing
	 * to do with the following tests, bus and connection
	 * creation nor connection update, but we do it so we are
	 * sure that everything work as expected
	 */

	attach_flags_mask = 0;
	ret = kdbus_sysfs_set_parameter_mask(env->mask_param_path,
					     attach_flags_mask);
	ASSERT_RETURN(ret == 0);


	/*
	 * Create bus with a full set of ATTACH flags
	 */

	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peer-flags-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, _KDBUS_ATTACH_ALL,
			       &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	/*
	 * Create a connection with an empty send attach flags, or
	 * with just KDBUS_ATTACH_CREDS, this should fail
	 */
	conn = __kdbus_hello(buspath, 0, 0, 0);
	ASSERT_RETURN(conn == NULL);
	ASSERT_RETURN(errno == ECONNREFUSED);

	conn = __kdbus_hello(buspath, 0, KDBUS_ATTACH_CREDS,
			     _KDBUS_ATTACH_ALL);
	ASSERT_RETURN(conn == NULL);
	ASSERT_RETURN(errno == ECONNREFUSED);

	conn = __kdbus_hello(buspath, 0, _KDBUS_ATTACH_ALL, 0);
	ASSERT_RETURN(conn);

	/* Try to cut back some send attach flags */
	ret = kdbus_conn_update_attach_flags(conn,
					     KDBUS_ATTACH_CREDS|
					     KDBUS_ATTACH_PIDS,
					     _KDBUS_ATTACH_ALL);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_conn_update_attach_flags(conn,
					     _KDBUS_ATTACH_ALL, 0);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);
	free(path);
	free(busname);
	close(control_fd);


	/* Test a new bus with KDBUS_ATTACH_PIDS */

	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peer-flags-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, KDBUS_ATTACH_PIDS,
			       &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	/*
	 * Create a connection with an empty send attach flags, or
	 * all flags except KDBUS_ATTACH_PIDS
	 */
	conn = __kdbus_hello(buspath, 0, 0, 0);
	ASSERT_RETURN(conn == NULL);
	ASSERT_RETURN(errno == ECONNREFUSED);

	conn = __kdbus_hello(buspath, 0,
			     _KDBUS_ATTACH_ALL & ~KDBUS_ATTACH_PIDS,
			     _KDBUS_ATTACH_ALL);
	ASSERT_RETURN(conn == NULL);
	ASSERT_RETURN(errno == ECONNREFUSED);

	/* The following should succeed */
	conn = __kdbus_hello(buspath, 0, KDBUS_ATTACH_PIDS, 0);
	ASSERT_RETURN(conn);
	kdbus_conn_free(conn);

	conn = __kdbus_hello(buspath, 0, _KDBUS_ATTACH_ALL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_conn_update_attach_flags(conn,
					     _KDBUS_ATTACH_ALL &
					     ~KDBUS_ATTACH_PIDS,
					     _KDBUS_ATTACH_ALL);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_conn_update_attach_flags(conn, 0,
					     _KDBUS_ATTACH_ALL);
	ASSERT_RETURN(ret == -EINVAL);

	/* Now we want only KDBUS_ATTACH_PIDS */
	ret = kdbus_conn_update_attach_flags(conn,
					     KDBUS_ATTACH_PIDS, 0);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);
	free(path);
	free(busname);
	close(control_fd);


	/*
	 * Create bus with 0 as ATTACH flags, the bus does not
	 * require any attach flags
	 */

	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peer-flags-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, 0, &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	/* Bus is open it does not require any send attach flags */
	conn = __kdbus_hello(buspath, 0, 0, 0);
	ASSERT_RETURN(conn);
	kdbus_conn_free(conn);

	conn = __kdbus_hello(buspath, 0, _KDBUS_ATTACH_ALL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_conn_update_attach_flags(conn, 0, 0);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_update_attach_flags(conn, KDBUS_ATTACH_CREDS, 0);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);
	free(path);
	free(busname);
	close(control_fd);

	return 0;
}

int kdbus_test_attach_flags(struct kdbus_test_env *env)
{
	int ret;
	uint64_t flags_mask;
	uint64_t old_kdbus_flags_mask;

	/* We need CAP_DAC_OVERRIDE to overwrite the kdbus mask */
	ret = test_is_capable(CAP_DAC_OVERRIDE, -1);
	ASSERT_RETURN(ret >= 0);

	/* no enough privileges, SKIP test */
	if (!ret)
		return TEST_SKIP;

	ret = kdbus_sysfs_get_parameter_mask(env->mask_param_path,
					     &old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test the bus peer attach flags
	 */
	ret = kdbus_bus_peer_flags(env);
	ASSERT_RETURN(ret == 0);

	/* Restore previous kdbus mask */
	ret = kdbus_sysfs_set_parameter_mask(env->mask_param_path,
					     old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_sysfs_get_parameter_mask(env->mask_param_path,
					     &flags_mask);
	ASSERT_RETURN(old_kdbus_flags_mask == flags_mask);

	return TEST_OK;
}
