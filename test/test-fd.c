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

#define KDBUS_MSG_MAX_ITEMS     128
#define KDBUS_MSG_MAX_FDS       253
#define KDBUS_USER_MAX_CONN	256

static int make_msg_payload_dbus(uint64_t src_id, uint64_t dst_id,
				 uint64_t msg_size,
				 struct kdbus_msg **msg_dbus)
{
	struct kdbus_msg *msg;

	msg = malloc(msg_size);
	ASSERT_RETURN_VAL(msg, -ENOMEM);

	memset(msg, 0, msg_size);
	msg->size = msg_size;
	msg->src_id = src_id;
	msg->dst_id = dst_id;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	*msg_dbus = msg;

	return 0;
}

static void make_item_memfds(struct kdbus_item *item,
			     int *memfds, size_t memfd_size)
{
	size_t i;

	for (i = 0; i < memfd_size; i++) {
		item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     sizeof(struct kdbus_memfd);
		item->memfd.fd = memfds[i];
		item->memfd.size = sizeof(uint64_t); /* const size */
		item = KDBUS_ITEM_NEXT(item);
	}
}

static void make_item_fds(struct kdbus_item *item,
			  int *fd_array, size_t fd_size)
{
	size_t i;
	item->type = KDBUS_ITEM_FDS;
	item->size = KDBUS_ITEM_HEADER_SIZE + (sizeof(int) * fd_size);

	for (i = 0; i < fd_size; i++)
		item->fds[i] = fd_array[i];
}

static int memfd_write(const char *name, void *buf, size_t bufsize)
{
	ssize_t ret;
	int memfd;

	memfd = sys_memfd_create(name, 0);
	ASSERT_RETURN_VAL(memfd >= 0, memfd);

	ret = write(memfd, buf, bufsize);
	ASSERT_RETURN_VAL(ret == (ssize_t)bufsize, -EAGAIN);

	ret = sys_memfd_seal_set(memfd);
	ASSERT_RETURN_VAL(ret == 0, -errno);

	return memfd;
}

static int send_memfds(struct kdbus_conn *conn, uint64_t dst_id,
		       int *memfds_array, size_t memfd_count)
{
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += memfd_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));

	ret = make_msg_payload_dbus(conn->id, dst_id, size, &msg);
	ASSERT_RETURN_VAL(ret == 0, ret);

	item = msg->items;

	make_item_memfds(item, memfds_array, memfd_count);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	free(msg);
	return 0;
}

static int send_fds(struct kdbus_conn *conn, uint64_t dst_id,
		    int *fd_array, size_t fd_count)
{
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(int) * fd_count);

	ret = make_msg_payload_dbus(conn->id, dst_id, size, &msg);
	ASSERT_RETURN_VAL(ret == 0, ret);

	item = msg->items;

	make_item_fds(item, fd_array, fd_count);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	free(msg);
	return ret;
}

static int send_fds_memfds(struct kdbus_conn *conn, uint64_t dst_id,
			   int *fds_array, size_t fd_count,
			   int *memfds_array, size_t memfd_count)
{
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += memfd_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
	size += KDBUS_ITEM_SIZE(sizeof(int) * fd_count);

	ret = make_msg_payload_dbus(conn->id, dst_id, size, &msg);
	ASSERT_RETURN_VAL(ret == 0, ret);

	item = msg->items;

	make_item_fds(item, fds_array, fd_count);
	item = KDBUS_ITEM_NEXT(item);
	make_item_memfds(item, memfds_array, memfd_count);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	free(msg);
	return ret;
}

static int kdbus_send_multiple_fds(struct kdbus_conn *conn_src,
				   struct kdbus_conn *conn_dst)
{
	int ret, i;
	int fds[KDBUS_MSG_MAX_FDS + 1];
	int memfds[KDBUS_MSG_MAX_ITEMS + 1];
	struct kdbus_msg *msg;
	uint64_t dummy_value;

	dummy_value = time(NULL);

	for (i = 0; i < KDBUS_MSG_MAX_FDS + 1; i++) {
		fds[i] = open("/dev/null", O_RDWR|O_CLOEXEC);
		ASSERT_RETURN_VAL(fds[i] >= 0, -errno);
	}

	/* Send KDBUS_MSG_MAX_FDS with one more fd */
	ret = send_fds(conn_src, conn_dst->id, fds, KDBUS_MSG_MAX_FDS + 1);
	ASSERT_RETURN(ret == -EMFILE);

	/* Retry with the correct KDBUS_MSG_MAX_FDS */
	ret = send_fds(conn_src, conn_dst->id, fds, KDBUS_MSG_MAX_FDS);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);

	for (i = 0; i < KDBUS_MSG_MAX_ITEMS + 1; i++, dummy_value++) {
		memfds[i] = memfd_write("memfd-name",
					&dummy_value,
					sizeof(dummy_value));
		ASSERT_RETURN_VAL(memfds[i] >= 0, memfds[i]);
	}

	/* Send KDBUS_MSG_MAX_FDS with one more memfd */
	ret = send_memfds(conn_src, conn_dst->id,
			  memfds, KDBUS_MSG_MAX_ITEMS + 1);
	ASSERT_RETURN(ret == -E2BIG);

	/* Retry with the correct KDBUS_MSG_MAX_ITEMS */
	ret = send_memfds(conn_src, conn_dst->id,
			  memfds, KDBUS_MSG_MAX_ITEMS);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);


	/* Combine multiple 154 fds and 100 memfds */
	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, 154, memfds, 100);
	ASSERT_RETURN(ret == -EMFILE);

	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, 153, memfds, 100);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);


	for (i = 0; i < KDBUS_MSG_MAX_FDS + 1; i++)
		close(fds[i]);

	for (i = 0; i < KDBUS_MSG_MAX_ITEMS + 1; i++)
		close(memfds[i]);

	return 0;
}

int kdbus_test_fd_passing(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_src, *conn_dst;
	const char *str = "stackenblocken";
	const struct kdbus_item *item;
	struct kdbus_msg *msg;
	unsigned int i;
	time_t now;
	int fds_conn[2];
	int fds[2];
	int memfd;
	int ret;

	now = time(NULL);

	/* create two connections */
	conn_src = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_dst = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_src && conn_dst);

	fds_conn[0] = conn_src->fd;
	fds_conn[1] = conn_dst->fd;

	/*
	 * Try to ass the handle of a connection as message payload.
	 * This must fail.
	 */
	ret = send_fds(conn_src, conn_dst->id, fds_conn, 2);
	ASSERT_RETURN(ret == -ENOTSUP);

	ret = send_fds(conn_src, conn_dst->id, fds_conn, 2);
	ASSERT_RETURN(ret == -ENOTSUP);

	ret = pipe(fds);
	ASSERT_RETURN(ret == 0);

	i = write(fds[1], str, strlen(str));
	ASSERT_RETURN(i == strlen(str));

	/* Try to broadcast file descriptors. This must fail. */
	ret = send_fds(conn_src, KDBUS_DST_ID_BROADCAST, fds, 1);
	ASSERT_RETURN(ret == -ENOTUNIQ);

	ret = send_fds(conn_src, conn_dst->id, fds, 1);
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

	kdbus_msg_free(msg);

	memfd = memfd_write("memfd-name", &now, sizeof(now));
	ASSERT_RETURN(memfd >= 0);

	/* Try to broadcast memfd. This must fail. */
	ret = send_memfds(conn_src, KDBUS_DST_ID_BROADCAST,
			  (int *)&memfd, 1);
	ASSERT_RETURN(ret == -ENOTUNIQ);

	ret = kdbus_send_multiple_fds(conn_src, conn_dst);
	ASSERT_RETURN(ret == 0);

	close(fds[0]);
	close(fds[1]);
	close(memfd);

	kdbus_conn_free(conn_src);
	kdbus_conn_free(conn_dst);

	return TEST_OK;
}
