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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/unistd.h>

#include "kdbus-api.h"
#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

/*
 * Should be the sum of the currently supported and compiled-in
 * KDBUS_ITEMS_* that reflect KDBUS_ATTACH_* flags.
 */
static unsigned int KDBUS_TEST_ITEMS_SUM = KDBUS_ATTACH_ITEMS_TYPE_SUM;

static struct kdbus_conn *__kdbus_hello(const char *path, uint64_t flags,
					uint64_t attach_flags_send,
					uint64_t attach_flags_recv)
{
	struct kdbus_cmd_free cmd_free = {};
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

	ret = kdbus_cmd_hello(fd, (struct kdbus_cmd_hello *) &h.hello);
	if (ret < 0) {
		kdbus_printf("--- error when saying hello: %d (%m)\n", ret);
		return NULL;
	}

	kdbus_printf("-- New connection ID : %llu\n",
		     (unsigned long long)h.hello.id);

	cmd_free.size = sizeof(cmd_free);
	cmd_free.offset = h.hello.offset;
	ret = kdbus_cmd_free(fd, &cmd_free);
	if (ret < 0)
		return NULL;

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

static int kdbus_test_peers_creation(struct kdbus_test_env *env)
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

	busname = unique_name("test-peers-creation-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, _KDBUS_ATTACH_ALL,
			       0, &path);
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
			       0, &path);
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

	ret = kdbus_create_bus(control_fd, busname, 0, 0, &path);
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

static int kdbus_test_peers_info(struct kdbus_test_env *env)
{
	int ret;
	int control_fd;
	char *path;
	char *busname;
	unsigned int i = 0;
	uint64_t offset = 0;
	char buspath[2048];
	char control_path[2048];
	uint64_t attach_flags_mask;
	struct kdbus_item *item;
	struct kdbus_info *info;
	struct kdbus_conn *conn;
	struct kdbus_conn *reader;
	unsigned long long attach_count = 0;

	snprintf(control_path, sizeof(control_path),
		 "%s/control", env->root);

	attach_flags_mask = 0;
	ret = kdbus_sysfs_set_parameter_mask(env->mask_param_path,
					     attach_flags_mask);
	ASSERT_RETURN(ret == 0);

	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peers-info-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, _KDBUS_ATTACH_ALL,
			       0, &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	/* Create connections with the appropriate flags */
	conn = __kdbus_hello(buspath, 0, _KDBUS_ATTACH_ALL, 0);
	ASSERT_RETURN(conn);

	reader = __kdbus_hello(buspath, 0, _KDBUS_ATTACH_ALL, 0);
	ASSERT_RETURN(reader);

	ret = kdbus_conn_info(reader, conn->id, NULL,
			      _KDBUS_ATTACH_ALL, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(reader->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	/* all attach flags are masked, no metadata */
	KDBUS_ITEM_FOREACH(item, info, items)
		i++;

	ASSERT_RETURN(i == 0);

	kdbus_free(reader, offset);

	/* Set the mask to _KDBUS_ATTACH_ANY */
	attach_flags_mask = _KDBUS_ATTACH_ANY;
	ret = kdbus_sysfs_set_parameter_mask(env->mask_param_path,
					     attach_flags_mask);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_info(reader, conn->id, NULL,
			      _KDBUS_ATTACH_ALL, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(reader->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	attach_count = 0;
	KDBUS_ITEM_FOREACH(item, info, items)
		    attach_count += item->type;

	/*
	 * All flags have been returned except for:
	 * KDBUS_ITEM_TIMESTAMP and
	 * KDBUS_ITEM_OWNED_NAME we do not own any name.
	 */
	ASSERT_RETURN(attach_count == (KDBUS_TEST_ITEMS_SUM -
				       KDBUS_ITEM_OWNED_NAME -
				       KDBUS_ITEM_TIMESTAMP));

	kdbus_free(reader, offset);

	/* Request only OWNED names */
	ret = kdbus_conn_info(reader, conn->id, NULL,
			      KDBUS_ATTACH_NAMES, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(reader->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	attach_count = 0;
	KDBUS_ITEM_FOREACH(item, info, items)
		attach_count += item->type;

	/* we should not get any metadata since we do not own names */
	ASSERT_RETURN(attach_count == 0);

	kdbus_free(reader, offset);

	kdbus_conn_free(conn);
	kdbus_conn_free(reader);

	return 0;
}

/**
 * @kdbus_mask_param:	kdbus module mask parameter (system-wide)
 * @requested_meta:	The bus owner metadata that we want
 * @expected_items:	The returned KDBUS_ITEMS_* sum. Used to
 *			validate the returned metadata items
 */
static int kdbus_cmp_bus_creator_metadata(struct kdbus_test_env *env,
					  struct kdbus_conn *conn,
					  uint64_t kdbus_mask_param,
					  uint64_t requested_meta,
					  unsigned long expected_items)
{
	int ret;
	uint64_t offset = 0;
	struct kdbus_info *info;
	struct kdbus_item *item;
	unsigned long attach_count = 0;

	ret = kdbus_sysfs_set_parameter_mask(env->mask_param_path,
					     kdbus_mask_param);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_bus_creator_info(conn, requested_meta, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(conn->buf + offset);

	KDBUS_ITEM_FOREACH(item, info, items)
		attach_count += item->type;

	ASSERT_RETURN(attach_count == expected_items);

	ret = kdbus_free(conn, offset);
	ASSERT_RETURN(ret == 0);

	return 0;
}

static int kdbus_test_bus_creator_info(struct kdbus_test_env *env)
{
	int ret;
	int control_fd;
	char *path;
	char *busname;
	char buspath[2048];
	char control_path[2048];
	uint64_t attach_flags_mask;
	struct kdbus_conn *conn;
	unsigned long expected_items = 0;

	snprintf(control_path, sizeof(control_path),
		 "%s/control", env->root);

	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peers-info-bus");
	ASSERT_RETURN(busname);

	/*
	 * Now the bus allows us to see all its KDBUS_ATTACH_*
	 * items
	 */
	ret = kdbus_create_bus(control_fd, busname, 0,
			       _KDBUS_ATTACH_ALL, &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	conn = __kdbus_hello(buspath, 0, 0, 0);
	ASSERT_RETURN(conn);

	/*
	 * Start with a kdbus module mask set to _KDBUS_ATTACH_ANY
	 */
	attach_flags_mask = _KDBUS_ATTACH_ANY;

	/*
	 * All flags will be returned except for:
	 * KDBUS_ITEM_TIMESTAMP
	 * KDBUS_ITEM_OWNED_NAME
	 * KDBUS_ITEM_CONN_DESCRIPTION
	 *
	 * An extra flags is always returned KDBUS_ITEM_MAKE_NAME
	 * which contains the bus name
	 */
	expected_items = KDBUS_TEST_ITEMS_SUM + KDBUS_ITEM_MAKE_NAME;
	expected_items -= KDBUS_ITEM_TIMESTAMP +
			  KDBUS_ITEM_OWNED_NAME +
			  KDBUS_ITEM_CONN_DESCRIPTION;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	/*
	 * We should have:
	 * KDBUS_ITEM_PIDS + KDBUS_ITEM_CREDS + KDBUS_ITEM_MAKE_NAME
	 */
	expected_items = KDBUS_ITEM_PIDS + KDBUS_ITEM_CREDS +
			 KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     KDBUS_ATTACH_PIDS |
					     KDBUS_ATTACH_CREDS,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	/* KDBUS_ITEM_MAKE_NAME is always returned */
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     0, expected_items);
	ASSERT_RETURN(ret == 0);

	/*
	 * Restrict kdbus system-wide mask to KDBUS_ATTACH_PIDS
	 */

	attach_flags_mask = KDBUS_ATTACH_PIDS;

	/*
	 * We should have:
	 * KDBUS_ITEM_PIDS + KDBUS_ITEM_MAKE_NAME
	 */
	expected_items = KDBUS_ITEM_PIDS + KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);


	/* system-wide mask to 0 */
	attach_flags_mask = 0;

	/* we should only see: KDBUS_ITEM_MAKE_NAME */
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);
	free(path);
	free(busname);
	close(control_fd);


	/*
	 * A new bus that hides all its owner metadata
	 */

	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peers-info-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, 0, 0, &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	conn = __kdbus_hello(buspath, 0, 0, 0);
	ASSERT_RETURN(conn);

	/*
	 * Start with a kdbus module mask set to _KDBUS_ATTACH_ANY
	 */
	attach_flags_mask = _KDBUS_ATTACH_ANY;

	/*
	 * We only get the KDBUS_ITEM_MAKE_NAME
	 */
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	/*
	 * We still get only kdbus_ITEM_MAKE_NAME
	 */
	attach_flags_mask = 0;
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);
	free(path);
	free(busname);
	close(control_fd);


	/*
	 * A new bus that shows only the PID and CREDS metadata
	 * of the bus owner.
	 */
	control_fd = open(control_path, O_RDWR);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-peers-info-bus");
	ASSERT_RETURN(busname);

	ret = kdbus_create_bus(control_fd, busname, 0,
			       KDBUS_ATTACH_PIDS|
			       KDBUS_ATTACH_CREDS, &path);
	ASSERT_RETURN(ret == 0);

	snprintf(buspath, sizeof(buspath), "%s/%s/bus", env->root, path);

	conn = __kdbus_hello(buspath, 0, 0, 0);
	ASSERT_RETURN(conn);

	/*
	 * Start with a kdbus module mask set to _KDBUS_ATTACH_ANY
	 */
	attach_flags_mask = _KDBUS_ATTACH_ANY;

	/*
	 * We should have:
	 * KDBUS_ITEM_PIDS + KDBUS_ITEM_CREDS + KDBUS_ITEM_MAKE_NAME
	 */
	expected_items = KDBUS_ITEM_PIDS + KDBUS_ITEM_CREDS +
			 KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	expected_items = KDBUS_ITEM_CREDS + KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     KDBUS_ATTACH_CREDS,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	/* KDBUS_ITEM_MAKE_NAME is always returned */
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     0, expected_items);
	ASSERT_RETURN(ret == 0);

	/*
	 * Restrict kdbus system-wide mask to KDBUS_ATTACH_PIDS
	 */

	attach_flags_mask = KDBUS_ATTACH_PIDS;
	/*
	 * We should have:
	 * KDBUS_ITEM_PIDS + KDBUS_ITEM_MAKE_NAME
	 */
	expected_items = KDBUS_ITEM_PIDS + KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	/* No KDBUS_ATTACH_CREDS */
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     KDBUS_ATTACH_CREDS,
					     expected_items);
	ASSERT_RETURN(ret == 0);

	/* system-wide mask to 0 */
	attach_flags_mask = 0;

	/* we should only see: KDBUS_ITEM_MAKE_NAME */
	expected_items = KDBUS_ITEM_MAKE_NAME;
	ret = kdbus_cmp_bus_creator_metadata(env, conn,
					     attach_flags_mask,
					     _KDBUS_ATTACH_ALL,
					     expected_items);
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

	/*
	 * We need to be able to write to
	 * "/sys/module/kdbus/parameters/attach_flags_mask"
	 * perhaps we are unprvileged/privileged in its userns
	 */
	ret = access(env->mask_param_path, W_OK);
	if (ret < 0) {
		kdbus_printf("--- access() '%s' failed: %d (%m)\n",
			     env->mask_param_path, -errno);
		return TEST_SKIP;
	}

	ret = kdbus_sysfs_get_parameter_mask(env->mask_param_path,
					     &old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	/* setup the right KDBUS_TEST_ITEMS_SUM */
	if (!config_auditsyscall_is_enabled())
		KDBUS_TEST_ITEMS_SUM -= KDBUS_ITEM_AUDIT;

	if (!config_cgroups_is_enabled())
		KDBUS_TEST_ITEMS_SUM -= KDBUS_ITEM_CGROUP;

	if (!config_security_is_enabled())
		KDBUS_TEST_ITEMS_SUM -= KDBUS_ITEM_SECLABEL;

	/*
	 * Test the connection creation attach flags
	 */
	ret = kdbus_test_peers_creation(env);
	/* Restore previous kdbus mask */
	kdbus_sysfs_set_parameter_mask(env->mask_param_path,
				       old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test the CONN_INFO attach flags
	 */
	ret = kdbus_test_peers_info(env);
	/* Restore previous kdbus mask */
	kdbus_sysfs_set_parameter_mask(env->mask_param_path,
				       old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test the Bus creator info and its attach flags
	 */
	ret = kdbus_test_bus_creator_info(env);
	/* Restore previous kdbus mask */
	kdbus_sysfs_set_parameter_mask(env->mask_param_path,
				       old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_sysfs_get_parameter_mask(env->mask_param_path,
					     &flags_mask);
	ASSERT_RETURN(ret == 0 && old_kdbus_flags_mask == flags_mask);

	return TEST_OK;
}
