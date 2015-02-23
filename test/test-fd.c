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
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "kdbus-api.h"
#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#define KDBUS_MSG_MAX_ITEMS     128
#define KDBUS_USER_MAX_CONN	256

/* maximum number of inflight fds in a target queue per user */
#define KDBUS_CONN_MAX_FDS_PER_USER	16

/* maximum number of memfd items per message */
#define KDBUS_MSG_MAX_MEMFD_ITEMS       16

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
	struct kdbus_cmd_send cmd = {};
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += memfd_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));

	if (dst_id == KDBUS_DST_ID_BROADCAST)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + 64;

	ret = make_msg_payload_dbus(conn->id, dst_id, size, &msg);
	ASSERT_RETURN_VAL(ret == 0, ret);

	item = msg->items;

	if (dst_id == KDBUS_DST_ID_BROADCAST) {
		item->type = KDBUS_ITEM_BLOOM_FILTER;
		item->size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + 64;
		item = KDBUS_ITEM_NEXT(item);

		msg->flags |= KDBUS_MSG_SIGNAL;
	}

	make_item_memfds(item, memfds_array, memfd_count);

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	ret = kdbus_cmd_send(conn->fd, &cmd);
	if (ret < 0) {
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	free(msg);
	return 0;
}

static int send_fds(struct kdbus_conn *conn, uint64_t dst_id,
		    int *fd_array, size_t fd_count)
{
	struct kdbus_cmd_send cmd = {};
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(int) * fd_count);

	if (dst_id == KDBUS_DST_ID_BROADCAST)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + 64;

	ret = make_msg_payload_dbus(conn->id, dst_id, size, &msg);
	ASSERT_RETURN_VAL(ret == 0, ret);

	item = msg->items;

	if (dst_id == KDBUS_DST_ID_BROADCAST) {
		item->type = KDBUS_ITEM_BLOOM_FILTER;
		item->size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + 64;
		item = KDBUS_ITEM_NEXT(item);

		msg->flags |= KDBUS_MSG_SIGNAL;
	}

	make_item_fds(item, fd_array, fd_count);

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	ret = kdbus_cmd_send(conn->fd, &cmd);
	if (ret < 0) {
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
	struct kdbus_cmd_send cmd = {};
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

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	ret = kdbus_cmd_send(conn->fd, &cmd);
	if (ret < 0) {
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	free(msg);
	return ret;
}

/* Return the number of received fds */
static unsigned int kdbus_item_get_nfds(struct kdbus_msg *msg)
{
	unsigned int fds = 0;
	const struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, msg, items) {
		switch (item->type) {
		case KDBUS_ITEM_FDS: {
			fds += (item->size - KDBUS_ITEM_HEADER_SIZE) /
				sizeof(int);
			break;
		}

		case KDBUS_ITEM_PAYLOAD_MEMFD:
			fds++;
			break;

		default:
			break;
		}
	}

	return fds;
}

static struct kdbus_msg *
get_kdbus_msg_with_fd(struct kdbus_conn *conn_src,
		      uint64_t dst_id, uint64_t cookie, int fd)
{
	int ret;
	uint64_t size;
	struct kdbus_item *item;
	struct kdbus_msg *msg;

	size = sizeof(struct kdbus_msg);
	if (fd >= 0)
		size += KDBUS_ITEM_SIZE(sizeof(int));

	ret = make_msg_payload_dbus(conn_src->id, dst_id, size, &msg);
	ASSERT_RETURN_VAL(ret == 0, NULL);

	msg->cookie = cookie;

	if (fd >= 0) {
		item = msg->items;

		make_item_fds(item, (int *)&fd, 1);
	}

	return msg;
}

static int kdbus_test_no_fds(struct kdbus_test_env *env,
			     int *fds, int *memfd)
{
	pid_t pid;
	int ret, status;
	uint64_t cookie;
	int connfd1, connfd2;
	struct kdbus_msg *msg, *msg_sync_reply;
	struct kdbus_cmd_hello hello;
	struct kdbus_conn *conn_src, *conn_dst, *conn_dummy;
	struct kdbus_cmd_send cmd = {};
	struct kdbus_cmd_free cmd_free = {};

	conn_src = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_src);

	connfd1 = open(env->buspath, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(connfd1 >= 0);

	connfd2 = open(env->buspath, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(connfd2 >= 0);

	/*
	 * Create connections without KDBUS_HELLO_ACCEPT_FD
	 * to test if send fd operations are blocked
	 */
	conn_dst = malloc(sizeof(*conn_dst));
	ASSERT_RETURN(conn_dst);

	conn_dummy = malloc(sizeof(*conn_dummy));
	ASSERT_RETURN(conn_dummy);

	memset(&hello, 0, sizeof(hello));
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;

	ret = kdbus_cmd_hello(connfd1, &hello);
	ASSERT_RETURN(ret == 0);

	cmd_free.size = sizeof(cmd_free);
	cmd_free.offset = hello.offset;
	ret = kdbus_cmd_free(connfd1, &cmd_free);
	ASSERT_RETURN(ret >= 0);

	conn_dst->fd = connfd1;
	conn_dst->id = hello.id;

	memset(&hello, 0, sizeof(hello));
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;

	ret = kdbus_cmd_hello(connfd2, &hello);
	ASSERT_RETURN(ret == 0);

	cmd_free.size = sizeof(cmd_free);
	cmd_free.offset = hello.offset;
	ret = kdbus_cmd_free(connfd2, &cmd_free);
	ASSERT_RETURN(ret >= 0);

	conn_dummy->fd = connfd2;
	conn_dummy->id = hello.id;

	conn_dst->buf = mmap(NULL, POOL_SIZE, PROT_READ,
			     MAP_SHARED, connfd1, 0);
	ASSERT_RETURN(conn_dst->buf != MAP_FAILED);

	conn_dummy->buf = mmap(NULL, POOL_SIZE, PROT_READ,
			       MAP_SHARED, connfd2, 0);
	ASSERT_RETURN(conn_dummy->buf != MAP_FAILED);

	/*
	 * Send fds to connection that do not accept fd passing
	 */
	ret = send_fds(conn_src, conn_dst->id, fds, 1);
	ASSERT_RETURN(ret == -ECOMM);

	/*
	 * memfd are kdbus payload
	 */
	ret = send_memfds(conn_src, conn_dst->id, memfd, 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv_poll(conn_dst, 100, NULL, NULL);
	ASSERT_RETURN(ret == 0);

	cookie = time(NULL);

	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, pid);

	if (pid == 0) {
		struct timespec now;

		/*
		 * A sync send/reply to a connection that do not
		 * accept fds should fail if it contains an fd
		 */
		msg_sync_reply = get_kdbus_msg_with_fd(conn_dst,
						       conn_dummy->id,
						       cookie, fds[0]);
		ASSERT_EXIT(msg_sync_reply);

		ret = clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
		ASSERT_EXIT(ret == 0);

		msg_sync_reply->timeout_ns = now.tv_sec * 1000000000ULL +
					     now.tv_nsec + 100000000ULL;
		msg_sync_reply->flags = KDBUS_MSG_EXPECT_REPLY;

		memset(&cmd, 0, sizeof(cmd));
		cmd.size = sizeof(cmd);
		cmd.msg_address = (uintptr_t)msg_sync_reply;
		cmd.flags = KDBUS_SEND_SYNC_REPLY;

		ret = kdbus_cmd_send(conn_dst->fd, &cmd);
		ASSERT_EXIT(ret == -ECOMM);

		/*
		 * Now send a normal message, but the sync reply
		 * will fail since it contains an fd that the
		 * original sender do not want.
		 *
		 * The original sender will fail with -ETIMEDOUT
		 */
		cookie++;
		ret = kdbus_msg_send_sync(conn_dst, NULL, cookie,
					  KDBUS_MSG_EXPECT_REPLY,
					  5000000000ULL, 0, conn_src->id, -1);
		ASSERT_EXIT(ret == -EREMOTEIO);

		cookie++;
		ret = kdbus_msg_recv_poll(conn_dst, 100, &msg, NULL);
		ASSERT_EXIT(ret == 0);
		ASSERT_EXIT(msg->cookie == cookie);

		free(msg_sync_reply);
		kdbus_msg_free(msg);

		_exit(EXIT_SUCCESS);
	}

	ret = kdbus_msg_recv_poll(conn_dummy, 100, NULL, NULL);
	ASSERT_RETURN(ret == -ETIMEDOUT);

	cookie++;
	ret = kdbus_msg_recv_poll(conn_src, 100, &msg, NULL);
	ASSERT_RETURN(ret == 0 && msg->cookie == cookie);

	kdbus_msg_free(msg);

	/*
	 * Try to reply with a kdbus connection handle, this should
	 * fail with -EOPNOTSUPP
	 */
	msg_sync_reply = get_kdbus_msg_with_fd(conn_src,
					       conn_dst->id,
					       cookie, conn_dst->fd);
	ASSERT_RETURN(msg_sync_reply);

	msg_sync_reply->cookie_reply = cookie;

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg_sync_reply;

	ret = kdbus_cmd_send(conn_src->fd, &cmd);
	ASSERT_RETURN(ret == -EOPNOTSUPP);

	free(msg_sync_reply);

	/*
	 * Try to reply with a normal fd, this should fail even
	 * if the response is a sync reply
	 *
	 * From the sender view we fail with -ECOMM
	 */
	msg_sync_reply = get_kdbus_msg_with_fd(conn_src,
					       conn_dst->id,
					       cookie, fds[0]);
	ASSERT_RETURN(msg_sync_reply);

	msg_sync_reply->cookie_reply = cookie;

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg_sync_reply;

	ret = kdbus_cmd_send(conn_src->fd, &cmd);
	ASSERT_RETURN(ret == -ECOMM);

	free(msg_sync_reply);

	/*
	 * Resend another normal message and check if the queue
	 * is clear
	 */
	cookie++;
	ret = kdbus_msg_send(conn_src, NULL, cookie, 0, 0, 0,
			     conn_dst->id);
	ASSERT_RETURN(ret == 0);

	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN_VAL(ret >= 0, ret);

	kdbus_conn_free(conn_dummy);
	kdbus_conn_free(conn_dst);
	kdbus_conn_free(conn_src);

	return (status == EXIT_SUCCESS) ? TEST_OK : TEST_ERR;
}

static int kdbus_send_multiple_fds(struct kdbus_conn *conn_src,
				   struct kdbus_conn *conn_dst)
{
	int ret, i;
	unsigned int nfds;
	int fds[KDBUS_CONN_MAX_FDS_PER_USER + 1];
	int memfds[KDBUS_MSG_MAX_ITEMS + 1];
	struct kdbus_msg *msg;
	uint64_t dummy_value;

	dummy_value = time(NULL);

	for (i = 0; i < KDBUS_CONN_MAX_FDS_PER_USER + 1; i++) {
		fds[i] = open("/dev/null", O_RDWR|O_CLOEXEC);
		ASSERT_RETURN_VAL(fds[i] >= 0, -errno);
	}

	/* Send KDBUS_CONN_MAX_FDS_PER_USER with one more fd */
	ret = send_fds(conn_src, conn_dst->id, fds,
		       KDBUS_CONN_MAX_FDS_PER_USER + 1);
	ASSERT_RETURN(ret == -EMFILE);

	/* Retry with the correct KDBUS_CONN_MAX_FDS_PER_USER */
	ret = send_fds(conn_src, conn_dst->id, fds,
		       KDBUS_CONN_MAX_FDS_PER_USER);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	/* Check we got the right number of fds */
	nfds = kdbus_item_get_nfds(msg);
	ASSERT_RETURN(nfds == KDBUS_CONN_MAX_FDS_PER_USER);

	kdbus_msg_free(msg);

	for (i = 0; i < KDBUS_MSG_MAX_ITEMS + 1; i++, dummy_value++) {
		memfds[i] = memfd_write("memfd-name",
					&dummy_value,
					sizeof(dummy_value));
		ASSERT_RETURN_VAL(memfds[i] >= 0, memfds[i]);
	}

	/* Send KDBUS_MSG_MAX_ITEMS with one more memfd */
	ret = send_memfds(conn_src, conn_dst->id,
			  memfds, KDBUS_MSG_MAX_ITEMS + 1);
	ASSERT_RETURN(ret == -E2BIG);

	ret = send_memfds(conn_src, conn_dst->id,
			  memfds, KDBUS_MSG_MAX_MEMFD_ITEMS + 1);
	ASSERT_RETURN(ret == -E2BIG);

	/* Retry with the correct KDBUS_MSG_MAX_ITEMS */
	ret = send_memfds(conn_src, conn_dst->id,
			  memfds, KDBUS_MSG_MAX_MEMFD_ITEMS);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	/* Check we got the right number of fds */
	nfds = kdbus_item_get_nfds(msg);
	ASSERT_RETURN(nfds == KDBUS_MSG_MAX_MEMFD_ITEMS);

	kdbus_msg_free(msg);


	/*
	 * Combine multiple KDBUS_CONN_MAX_FDS_PER_USER+1 fds and
	 * 10 memfds
	 */
	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, KDBUS_CONN_MAX_FDS_PER_USER + 1,
			      memfds, 10);
	ASSERT_RETURN(ret == -EMFILE);

	ret = kdbus_msg_recv(conn_dst, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/*
	 * Combine multiple KDBUS_CONN_MAX_FDS_PER_USER fds and
	 * (128 - 1) + 1 memfds, all fds take one item, while each
	 * memfd takes one item
	 */
	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, KDBUS_CONN_MAX_FDS_PER_USER,
			      memfds, (KDBUS_MSG_MAX_ITEMS - 1) + 1);
	ASSERT_RETURN(ret == -E2BIG);

	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, KDBUS_CONN_MAX_FDS_PER_USER,
			      memfds, KDBUS_MSG_MAX_MEMFD_ITEMS + 1);
	ASSERT_RETURN(ret == -E2BIG);

	ret = kdbus_msg_recv(conn_dst, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/*
	 * Send KDBUS_CONN_MAX_FDS_PER_USER fds +
	 * KDBUS_MSG_MAX_MEMFD_ITEMS memfds
	 */
	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, KDBUS_CONN_MAX_FDS_PER_USER,
			      memfds, KDBUS_MSG_MAX_MEMFD_ITEMS);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	/* Check we got the right number of fds */
	nfds = kdbus_item_get_nfds(msg);
	ASSERT_RETURN(nfds == KDBUS_CONN_MAX_FDS_PER_USER +
			      KDBUS_MSG_MAX_MEMFD_ITEMS);

	kdbus_msg_free(msg);


	/*
	 * Re-send fds + memfds, close them, but do not receive them
	 * and try to queue more
	 */
	ret = send_fds_memfds(conn_src, conn_dst->id,
			      fds, KDBUS_CONN_MAX_FDS_PER_USER,
			      memfds, KDBUS_MSG_MAX_MEMFD_ITEMS);
	ASSERT_RETURN(ret == 0);

	/* close old references and get a new ones */
	for (i = 0; i < KDBUS_CONN_MAX_FDS_PER_USER + 1; i++) {
		close(fds[i]);
		fds[i] = open("/dev/null", O_RDWR|O_CLOEXEC);
		ASSERT_RETURN_VAL(fds[i] >= 0, -errno);
	}

	/* should fail since we have already fds in the queue */
	ret = send_fds(conn_src, conn_dst->id, fds,
		       KDBUS_CONN_MAX_FDS_PER_USER);
	ASSERT_RETURN(ret == -EMFILE);

	/* This should succeed */
	ret = send_memfds(conn_src, conn_dst->id,
			  memfds, KDBUS_MSG_MAX_MEMFD_ITEMS);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	nfds = kdbus_item_get_nfds(msg);
	ASSERT_RETURN(nfds == KDBUS_CONN_MAX_FDS_PER_USER +
			      KDBUS_MSG_MAX_MEMFD_ITEMS);

	kdbus_msg_free(msg);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	nfds = kdbus_item_get_nfds(msg);
	ASSERT_RETURN(nfds == KDBUS_MSG_MAX_MEMFD_ITEMS);

	kdbus_msg_free(msg);

	ret = kdbus_msg_recv(conn_dst, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	for (i = 0; i < KDBUS_CONN_MAX_FDS_PER_USER + 1; i++)
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
	uint64_t now;
	int fds_conn[2];
	int sock_pair[2];
	int fds[2];
	int memfd;
	int ret;

	now = (uint64_t) time(NULL);

	/* create two connections */
	conn_src = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_dst = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_src && conn_dst);

	fds_conn[0] = conn_src->fd;
	fds_conn[1] = conn_dst->fd;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_pair);
	ASSERT_RETURN(ret == 0);

	/* Setup memfd */
	memfd = memfd_write("memfd-name", &now, sizeof(now));
	ASSERT_RETURN(memfd >= 0);

	/* Setup pipes */
	ret = pipe(fds);
	ASSERT_RETURN(ret == 0);

	i = write(fds[1], str, strlen(str));
	ASSERT_RETURN(i == strlen(str));

	/*
	 * Try to ass the handle of a connection as message payload.
	 * This must fail.
	 */
	ret = send_fds(conn_src, conn_dst->id, fds_conn, 2);
	ASSERT_RETURN(ret == -ENOTSUP);

	ret = send_fds(conn_dst, conn_src->id, fds_conn, 2);
	ASSERT_RETURN(ret == -ENOTSUP);

	ret = send_fds(conn_src, conn_dst->id, sock_pair, 2);
	ASSERT_RETURN(ret == -ENOTSUP);

	/*
	 * Send fds and memfds to connection that do not accept fds
	 */
	ret = kdbus_test_no_fds(env, fds, (int *)&memfd);
	ASSERT_RETURN(ret == 0);

	/* Try to broadcast file descriptors. This must fail. */
	ret = send_fds(conn_src, KDBUS_DST_ID_BROADCAST, fds, 1);
	ASSERT_RETURN(ret == -ENOTUNIQ);

	/* Try to broadcast memfd. This must succeed. */
	ret = send_memfds(conn_src, KDBUS_DST_ID_BROADCAST, (int *)&memfd, 1);
	ASSERT_RETURN(ret == 0);

	/* Open code this loop */
loop_send_fds:

	/*
	 * Send the read end of the pipe and close it.
	 */
	ret = send_fds(conn_src, conn_dst->id, fds, 1);
	ASSERT_RETURN(ret == 0);
	close(fds[0]);

	ret = kdbus_msg_recv(conn_dst, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	KDBUS_ITEM_FOREACH(item, msg, items) {
		if (item->type == KDBUS_ITEM_FDS) {
			char tmp[14];
			int nfds = (item->size - KDBUS_ITEM_HEADER_SIZE) /
					sizeof(int);
			ASSERT_RETURN(nfds == 1);

			i = read(item->fds[0], tmp, sizeof(tmp));
			if (i != 0) {
				ASSERT_RETURN(i == sizeof(tmp));
				ASSERT_RETURN(memcmp(tmp, str, sizeof(tmp)) == 0);

				/* Write EOF */
				close(fds[1]);

				/*
				 * Resend the read end of the pipe,
				 * the receiver still holds a reference
				 * to it...
				 */
				goto loop_send_fds;
			}

			/* Got EOF */

			/*
			 * Close the last reference to the read end
			 * of the pipe, other references are
			 * automatically closed just after send.
			 */
			close(item->fds[0]);
		}
	}

	/*
	 * Try to resend the read end of the pipe. Must fail with
	 * -EBADF since both the sender and receiver closed their
	 * references to it. We assume the above since sender and
	 * receiver are on the same process.
	 */
	ret = send_fds(conn_src, conn_dst->id, fds, 1);
	ASSERT_RETURN(ret == -EBADF);

	/* Then we clear out received any data... */
	kdbus_msg_free(msg);

	ret = kdbus_send_multiple_fds(conn_src, conn_dst);
	ASSERT_RETURN(ret == 0);

	close(sock_pair[0]);
	close(sock_pair[1]);
	close(memfd);

	kdbus_conn_free(conn_src);
	kdbus_conn_free(conn_dst);

	return TEST_OK;
}
