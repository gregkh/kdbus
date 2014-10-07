#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#define KDBUS_USER_MAX_CONN	256

static int send_fd(struct kdbus_conn *conn, uint64_t dst_id, int fd)
{
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(int[2]));

	msg = alloca(size);

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = dst_id;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	item = msg->items;

	item->type = KDBUS_ITEM_FDS;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(int);
	item->fds[0] = fd;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret) {
		kdbus_printf("error sending message: %d err %d (%m)\n",
			     ret, errno);
		return -errno;
	}

	return 0;
}

int kdbus_test_fd_passing(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_src, *conn_dst;
	const char *str = "stackenblocken";
	const struct kdbus_item *item;
	struct kdbus_msg *msg;
	unsigned int i;
	int fds[2];
	int ret;

	/* create two connections */
	conn_src = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_dst = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_src && conn_dst);

	/*
	 * Try to ass the handle of a connection as message payload.
	 * This must fail.
	 */
	ret = send_fd(conn_src, conn_dst->id, conn_src->fd);
	ASSERT_RETURN(ret == -ENOTSUP);

	ret = send_fd(conn_src, conn_dst->id, conn_dst->fd);
	ASSERT_RETURN(ret == -ENOTSUP);

	ret = pipe(fds);
	ASSERT_RETURN(ret == 0);

	i = write(fds[1], str, strlen(str));
	ASSERT_RETURN(i == strlen(str));

	ret = send_fd(conn_src, conn_dst->id, fds[0]);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	KDBUS_ITEM_FOREACH(item, msg, items) {
		if (item->type == KDBUS_ITEM_FDS) {
			char tmp[14];
			int nfds = (item->size - KDBUS_ITEM_HEADER_SIZE) /
					sizeof(int);

			ASSERT_RETURN(nfds == 1);

			i = read(item->fds[0], tmp, sizeof(tmp));
			ASSERT_RETURN(i == sizeof(tmp));
			ASSERT_RETURN(memcmp(tmp, str, sizeof(tmp)) == 0);

			close(item->fds[0]);
		}
	}

	close(fds[0]);
	close(fds[1]);

	kdbus_conn_free(conn_src);
	kdbus_conn_free(conn_dst);

	return TEST_OK;
}
