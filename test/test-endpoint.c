#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/capability.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

#define KDBUS_SYSNAME_MAX_LEN			63

static int install_name_add_match(struct kdbus_conn *conn, const char *name)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_notify_name_change chg;
		} item;
		char name[64];
	} buf;
	int ret;

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.item.type = KDBUS_ITEM_NAME_ADD;
	buf.item.chg.old_id.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new_id.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.name, name, sizeof(buf.name) - 1);
	buf.item.size = sizeof(buf.item) + strlen(buf.name) + 1;
	buf.cmd.size = sizeof(buf.cmd) + buf.item.size;

	ret = kdbus_cmd_match_add(conn->fd, &buf.cmd);
	if (ret < 0)
		return ret;

	return 0;
}

static int create_endpoint(const char *buspath, uid_t uid, const char *name,
			   uint64_t flags)
{
	struct {
		struct kdbus_cmd cmd;

		/* name item */
		struct {
			uint64_t size;
			uint64_t type;
			/* max should be KDBUS_SYSNAME_MAX_LEN */
			char str[128];
		} name;
	} ep_make;
	int fd, ret;

	fd = open(buspath, O_RDWR);
	if (fd < 0)
		return fd;

	memset(&ep_make, 0, sizeof(ep_make));

	snprintf(ep_make.name.str,
		 /* Use the KDBUS_SYSNAME_MAX_LEN or sizeof(str) */
		 KDBUS_SYSNAME_MAX_LEN > strlen(name) ?
		 KDBUS_SYSNAME_MAX_LEN : sizeof(ep_make.name.str),
		 "%u-%s", uid, name);

	ep_make.name.type = KDBUS_ITEM_MAKE_NAME;
	ep_make.name.size = KDBUS_ITEM_HEADER_SIZE +
			    strlen(ep_make.name.str) + 1;

	ep_make.cmd.flags = flags;
	ep_make.cmd.size = sizeof(ep_make.cmd) + ep_make.name.size;

	ret = kdbus_cmd_endpoint_make(fd, &ep_make.cmd);
	if (ret < 0) {
		kdbus_printf("error creating endpoint: %d (%m)\n", ret);
		return ret;
	}

	return fd;
}

static int unpriv_test_custom_ep(const char *buspath)
{
	int ret, ep_fd1, ep_fd2;
	char *ep1, *ep2, *tmp1, *tmp2;

	tmp1 = strdup(buspath);
	tmp2 = strdup(buspath);
	ASSERT_RETURN(tmp1 && tmp2);

	ret = asprintf(&ep1, "%s/%u-%s", dirname(tmp1), getuid(), "apps1");
	ASSERT_RETURN(ret >= 0);

	ret = asprintf(&ep2, "%s/%u-%s", dirname(tmp2), getuid(), "apps2");
	ASSERT_RETURN(ret >= 0);

	free(tmp1);
	free(tmp2);

	/* endpoint only accessible to current uid */
	ep_fd1 = create_endpoint(buspath, getuid(), "apps1", 0);
	ASSERT_RETURN(ep_fd1 >= 0);

	/* endpoint world accessible */
	ep_fd2 = create_endpoint(buspath, getuid(), "apps2",
				  KDBUS_MAKE_ACCESS_WORLD);
	ASSERT_RETURN(ep_fd2 >= 0);

	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_UID, ({
		int ep_fd;
		struct kdbus_conn *ep_conn;

		/*
		 * Make sure that we are not able to create custom
		 * endpoints
		 */
		ep_fd = create_endpoint(buspath, getuid(),
					"unpriv_costum_ep", 0);
		ASSERT_EXIT(ep_fd == -EPERM);

		/*
		 * Endpoint "apps1" only accessible to same users,
		 * that own the endpoint. Access denied by VFS
		 */
		ep_conn = kdbus_hello(ep1, 0, NULL, 0);
		ASSERT_EXIT(!ep_conn && errno == EACCES);

		/* Endpoint "apps2" world accessible */
		ep_conn = kdbus_hello(ep2, 0, NULL, 0);
		ASSERT_EXIT(ep_conn);

		kdbus_conn_free(ep_conn);

		_exit(EXIT_SUCCESS);
	}),
	({ 0; }));
	ASSERT_RETURN(ret == 0);

	close(ep_fd1);
	close(ep_fd2);
	free(ep1);
	free(ep2);

	return 0;
}

static int update_endpoint(int fd, const char *name)
{
	int len = strlen(name) + 1;
	struct {
		struct kdbus_cmd cmd;

		/* name item */
		struct {
			uint64_t size;
			uint64_t type;
			char str[KDBUS_ALIGN8(len)];
		} name;

		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_policy_access access;
		} access;
	} ep_update;
	int ret;

	memset(&ep_update, 0, sizeof(ep_update));

	ep_update.name.size = KDBUS_ITEM_HEADER_SIZE + len;
	ep_update.name.type = KDBUS_ITEM_NAME;
	strncpy(ep_update.name.str, name, sizeof(ep_update.name.str) - 1);

	ep_update.access.size = sizeof(ep_update.access);
	ep_update.access.type = KDBUS_ITEM_POLICY_ACCESS;
	ep_update.access.access.type = KDBUS_POLICY_ACCESS_WORLD;
	ep_update.access.access.access = KDBUS_POLICY_SEE;

	ep_update.cmd.size = sizeof(ep_update);

	ret = kdbus_cmd_endpoint_update(fd, &ep_update.cmd);
	if (ret < 0) {
		kdbus_printf("error updating endpoint: %d (%m)\n", ret);
		return ret;
	}

	return 0;
}

int kdbus_test_custom_endpoint(struct kdbus_test_env *env)
{
	char *ep, *tmp;
	int ret, ep_fd;
	struct kdbus_msg *msg;
	struct kdbus_conn *ep_conn;
	struct kdbus_conn *reader;
	const char *name = "foo.bar.baz";
	const char *epname = "foo";
	char fake_ep[KDBUS_SYSNAME_MAX_LEN + 1] = {'\0'};

	memset(fake_ep, 'X', sizeof(fake_ep) - 1);

	/* Try to create a custom endpoint with a long name */
	ret = create_endpoint(env->buspath, getuid(), fake_ep, 0);
	ASSERT_RETURN(ret == -ENAMETOOLONG);

	/* Try to create a custom endpoint with a different uid */
	ret = create_endpoint(env->buspath, getuid() + 1, "foobar", 0);
	ASSERT_RETURN(ret == -EINVAL);

	/* create a custom endpoint, and open a connection on it */
	ep_fd = create_endpoint(env->buspath, getuid(), "foo", 0);
	ASSERT_RETURN(ep_fd >= 0);

	tmp = strdup(env->buspath);
	ASSERT_RETURN(tmp);

	ret = asprintf(&ep, "%s/%u-%s", dirname(tmp), getuid(), epname);
	free(tmp);
	ASSERT_RETURN(ret >= 0);

	/* Register a connection that listen to broadcasts */
	reader = kdbus_hello(ep, 0, NULL, 0);
	ASSERT_RETURN(reader);

	/* Register to kernel signals */
	ret = kdbus_add_match_id(reader, 0x1, KDBUS_ITEM_ID_ADD,
				 KDBUS_MATCH_ID_ANY);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_id(reader, 0x2, KDBUS_ITEM_ID_REMOVE,
				 KDBUS_MATCH_ID_ANY);
	ASSERT_RETURN(ret == 0);

	ret = install_name_add_match(reader, name);
	ASSERT_RETURN(ret == 0);

	/* Monitor connections are not supported on custom endpoints */
	ep_conn = kdbus_hello(ep, KDBUS_HELLO_MONITOR, NULL, 0);
	ASSERT_RETURN(!ep_conn && errno == EOPNOTSUPP);

	ep_conn = kdbus_hello(ep, 0, NULL, 0);
	ASSERT_RETURN(ep_conn);

	/*
	 * Add a name add match on the endpoint connection, acquire name from
	 * the unfiltered connection, and make sure the filtered connection
	 * did not get the notification on the name owner change. Also, the
	 * endpoint connection may not be able to call conn_info, neither on
	 * the name nor on the ID.
	 */
	ret = install_name_add_match(ep_conn, name);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(ep_conn, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	ret = kdbus_conn_info(ep_conn, 0, name, 0, NULL);
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_conn_info(ep_conn, 0, "random.crappy.name", 0, NULL);
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_conn_info(ep_conn, env->conn->id, NULL, 0, NULL);
	ASSERT_RETURN(ret == -ENXIO);

	ret = kdbus_conn_info(ep_conn, 0x0fffffffffffffffULL, NULL, 0, NULL);
	ASSERT_RETURN(ret == -ENXIO);

	/* Check that the reader did not receive anything */
	ret = kdbus_msg_recv(reader, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/*
	 * Release the name again, update the custom endpoint policy,
	 * and try again. This time, the connection on the custom endpoint
	 * should have gotten it.
	 */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	ret = update_endpoint(ep_fd, name);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(ep_conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_NAME_ADD);
	ASSERT_RETURN(msg->items[0].name_change.old_id.id == 0);
	ASSERT_RETURN(msg->items[0].name_change.new_id.id == env->conn->id);
	ASSERT_RETURN(strcmp(msg->items[0].name_change.name, name) == 0);
	kdbus_msg_free(msg);

	ret = kdbus_msg_recv(reader, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(strcmp(msg->items[0].name_change.name, name) == 0);

	kdbus_msg_free(msg);

	ret = kdbus_conn_info(ep_conn, 0, name, 0, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_info(ep_conn, env->conn->id, NULL, 0, NULL);
	ASSERT_RETURN(ret == 0);

	/* If we have privileges test custom endpoints */
	ret = test_is_capable(CAP_SETUID, CAP_SETGID, -1);
	ASSERT_RETURN(ret >= 0);

	/*
	 * All uids/gids are mapped and we have the necessary caps
	 */
	if (ret && all_uids_gids_are_mapped()) {
		ret = unpriv_test_custom_ep(env->buspath);
		ASSERT_RETURN(ret == 0);
	}

	kdbus_conn_free(reader);
	kdbus_conn_free(ep_conn);
	close(ep_fd);

	return TEST_OK;
}
