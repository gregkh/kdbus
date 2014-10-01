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
	strncpy(buf.name, name, sizeof(buf.name));
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
			char str[32];
		} name;
	} ep_make;
	int fd, ret;

	fd = open(buspath, O_RDWR);
	if (fd < 0)
		return fd;

	memset(&ep_make, 0, sizeof(ep_make));

	snprintf(ep_make.name.str, sizeof(ep_make.name.str),
		 "%u-%s", getuid(), name);

	ep_make.name.type = KDBUS_ITEM_MAKE_NAME;
	ep_make.name.size = KDBUS_ITEM_HEADER_SIZE +
			    strlen(ep_make.name.str) + 1;

	ep_make.head.size = sizeof(ep_make.head) +
			    ep_make.name.size;

	ret = ioctl(fd, KDBUS_CMD_EP_MAKE, &ep_make);
	if (ret < 0)
		return ret;

	return fd;
}

int kdbus_test_custom_endpoint(struct kdbus_test_env *env)
{
	char *ep, *tmp;
	int ret, ep_fd;
	struct kdbus_msg *msg;
	struct kdbus_conn *ep_conn;
	const char *name = "foo.bar.baz";
	const char *epname = "foo";

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

	/* add a name add match */
	ret = install_name_add_match(ep_conn, name);
	ASSERT_RETURN(ret == 0);

	/* now acquire name from the unfiltered connection */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	/* the filtered endpoint should NOT have received a notification */
	ret = kdbus_msg_recv(ep_conn, &msg, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	kdbus_conn_free(ep_conn);
	close(ep_fd);

	return TEST_OK;
}
