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
#include <sys/ioctl.h>
#include <stdbool.h>

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

	ret = ioctl(conn->fd, KDBUS_CMD_MATCH_ADD, &buf);
	if (ret < 0)
		return ret;

	return 0;
}

static int create_endpoint(const char *buspath, const char *name)
{
	struct {
		struct kdbus_cmd_make head;

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
		 "%u-%s", getuid(), name);

	ep_make.name.type = KDBUS_ITEM_MAKE_NAME;
	ep_make.name.size = KDBUS_ITEM_HEADER_SIZE +
			    strlen(ep_make.name.str) + 1;

	ep_make.head.size = sizeof(ep_make.head) +
			    ep_make.name.size;

	ret = ioctl(fd, KDBUS_CMD_ENDPOINT_MAKE, &ep_make);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error creating endpoint: %d (%m)\n", ret);
		return ret;
	}

	return fd;
}

static int update_endpoint(int fd, const char *name)
{
	int len = strlen(name) + 1;
	struct {
		struct kdbus_cmd_update head;

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

	ep_update.head.size = sizeof(ep_update);

	ret = ioctl(fd, KDBUS_CMD_ENDPOINT_UPDATE, &ep_update);
	if (ret < 0) {
		ret = -errno;
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
	const char *name = "foo.bar.baz";
	const char *epname = "foo";
	char fake_ep[KDBUS_SYSNAME_MAX_LEN + 1] = {'\0'};

	memset(fake_ep, 'X', sizeof(fake_ep) - 1);

	/* Try to create a custom endpoint with a long name */
	ret = create_endpoint(env->buspath, fake_ep);
	ASSERT_RETURN(ret == -ENAMETOOLONG);

	/* create a custom endpoint, and open a connection on it */
	ep_fd = create_endpoint(env->buspath, "foo");
	ASSERT_RETURN(ep_fd >= 0);

	tmp = strdup(env->buspath);
	ASSERT_RETURN(tmp);

	ret = asprintf(&ep, "%s/%u-%s", dirname(tmp), getuid(), epname);
	free(tmp);
	ASSERT_RETURN(ret >= 0);

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

	ret = kdbus_info(ep_conn, 0, name, 0, NULL);
	ASSERT_RETURN(ret == -ENOENT);

	ret = kdbus_info(ep_conn, env->conn->id, NULL, 0, NULL);
	ASSERT_RETURN(ret == -ENOENT);

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

	ret = kdbus_info(ep_conn, 0, name, 0, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_info(ep_conn, env->conn->id, NULL, 0, NULL);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(ep_conn);
	close(ep_fd);

	return TEST_OK;
}
