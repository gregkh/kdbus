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
#include <sys/types.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

int kdbus_test_hello(struct kdbus_test_env *env)
{
	struct kdbus_cmd_hello hello;
	int fd, ret;

	memset(&hello, 0, sizeof(hello));

	fd = open(env->buspath, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(fd >= 0);

	hello.flags = KDBUS_HELLO_ACCEPT_FD;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	hello.attach_flags_recv = _KDBUS_ATTACH_ALL;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;

	/* an unaligned hello must result in -EFAULT */
	ret = ioctl(fd, KDBUS_CMD_HELLO, (char *) &hello + 1);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	/* a size of 0 must return EMSGSIZE */
	hello.size = 1;
	hello.flags = KDBUS_HELLO_ACCEPT_FD;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	hello.size = sizeof(struct kdbus_cmd_hello);

	/* check faulty flags */
	hello.flags = 1ULL << 32;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	/* kernel must have set its bit in the ioctl buffer */
	ASSERT_RETURN(hello.kernel_flags & KDBUS_FLAG_KERNEL);

	/* check for faulty pool sizes */
	hello.pool_size = 0;
	hello.flags = KDBUS_HELLO_ACCEPT_FD;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	hello.pool_size = 4097;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	hello.pool_size = POOL_SIZE;

	/*
	 * The connection created by the core requires ALL meta flags
	 * to be sent. An attempt to send less that that should result
	 * in -ECONNREFUSED.
	 */
	hello.attach_flags_send = _KDBUS_ATTACH_ALL & ~KDBUS_ATTACH_TIMESTAMP;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == ECONNREFUSED);

	hello.attach_flags_send = _KDBUS_ATTACH_ALL;

	/* success test */
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == 0);

	/* The kernel should have set KDBUS_FLAG_KERNEL */
	ASSERT_RETURN(hello.attach_flags_send & KDBUS_FLAG_KERNEL);

	close(fd);

	fd = open(env->buspath, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(fd >= 0);

	/* no ACTIVATOR flag without a name */
	hello.flags = KDBUS_HELLO_ACTIVATOR;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	close(fd);

	return TEST_OK;
}

int kdbus_test_byebye(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct kdbus_cmd_recv recv = {};
	int ret;

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	ret = kdbus_add_match_empty(conn);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(env->conn);
	ASSERT_RETURN(ret == 0);

	/* send over 1st connection */
	ret = kdbus_msg_send(env->conn, NULL, 0, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* say byebye on the 2nd, which must fail */
	ret = ioctl(conn->fd, KDBUS_CMD_BYEBYE, 0);
	ASSERT_RETURN(ret == -1 && errno == EBUSY);

	/* receive the message */
	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_free(conn, recv.offset);
	ASSERT_RETURN(ret == 0);

	/* and try again */
	ret = ioctl(conn->fd, KDBUS_CMD_BYEBYE, 0);
	ASSERT_RETURN(ret == 0);

	/* a 2nd try should result in -EALREADY */
	ret = ioctl(conn->fd, KDBUS_CMD_BYEBYE, 0);
	ASSERT_RETURN(ret == -1 && errno == EALREADY);

	kdbus_conn_free(conn);

	return TEST_OK;
}

/* Get only the first item */
static struct kdbus_item *kdbus_get_item(struct kdbus_info *info,
					 uint64_t type)
{
	struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, info, items)
		if (item->type == type)
			return item;

	return NULL;
}

static unsigned int kdbus_count_item(struct kdbus_info *info,
				     uint64_t type)
{
	unsigned int i = 0;
	const struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, info, items)
		if (item->type == type)
			i++;

	return i;
}

static int kdbus_fuzz_conn_info(struct kdbus_test_env *env)
{
	int ret;
	unsigned int cnt = 0;
	uint64_t offset = 0;
	struct kdbus_info *info;
	struct kdbus_conn *conn;
	struct kdbus_conn *privileged;
	const struct kdbus_item *item;
	uint64_t valid_flags = KDBUS_ATTACH_NAMES |
			       KDBUS_ATTACH_CREDS |
			       KDBUS_ATTACH_CONN_DESCRIPTION;

	uint64_t invalid_flags = KDBUS_ATTACH_NAMES	|
				 KDBUS_ATTACH_CREDS	|
				 KDBUS_ATTACH_CAPS	|
				 KDBUS_ATTACH_CGROUP	|
				 KDBUS_ATTACH_CONN_DESCRIPTION;

	struct kdbus_creds cached_creds = {
		.uid	= getuid(),
		.gid	= getgid(),
		.pid	= getpid(),
		.tid	= syscall(SYS_gettid),
	};

	ret = kdbus_info(env->conn, env->conn->id, NULL,
			 valid_flags, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(env->conn->buf + offset);
	ASSERT_RETURN(info->id == env->conn->id);

	/* We do not have any well-known name */
	item = kdbus_get_item(info, KDBUS_ITEM_NAME);
	ASSERT_RETURN(item == NULL);

	item = kdbus_get_item(info, KDBUS_ITEM_CONN_DESCRIPTION);
	ASSERT_RETURN(item);

	kdbus_free(env->conn, offset);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	privileged = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(privileged);

	ret = kdbus_info(conn, conn->id, NULL, valid_flags, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(conn->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	/* We do not have any well-known name */
	item = kdbus_get_item(info, KDBUS_ITEM_NAME);
	ASSERT_RETURN(item == NULL);

	cnt = kdbus_count_item(info, KDBUS_ITEM_CREDS);
	ASSERT_RETURN(cnt == 1);

	item = kdbus_get_item(info, KDBUS_ITEM_CREDS);
	ASSERT_RETURN(item);

	/* Compare item->creds with cached creds */
	ASSERT_RETURN(item->creds.uid == cached_creds.uid &&
		      item->creds.gid == cached_creds.gid &&
		      item->creds.pid == cached_creds.pid &&
		      item->creds.tid == cached_creds.tid);

	/* We did not request KDBUS_ITEM_CAPS */
	item = kdbus_get_item(info, KDBUS_ITEM_CAPS);
	ASSERT_RETURN(item == NULL);

	kdbus_free(conn, offset);

	ret = kdbus_name_acquire(conn, "com.example.a", NULL);
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_info(conn, conn->id, NULL, valid_flags, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(conn->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	item = kdbus_get_item(info, KDBUS_ITEM_OWNED_NAME);
	ASSERT_RETURN(item && !strcmp(item->name.name, "com.example.a"));

	kdbus_free(conn, offset);

	ret = kdbus_info(conn, 0, "com.example.a", valid_flags, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(conn->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	kdbus_free(conn, offset);

	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_GID, ({
		ret = kdbus_info(conn, conn->id, NULL,
				 valid_flags, &offset);
		ASSERT_EXIT(ret == 0);

		info = (struct kdbus_info *)(conn->buf + offset);
		ASSERT_EXIT(info->id == conn->id);

		item = kdbus_get_item(info, KDBUS_ITEM_OWNED_NAME);
		ASSERT_EXIT(item &&
			!strcmp(item->name.name, "com.example.a"));

		item = kdbus_get_item(info, KDBUS_ITEM_CREDS);
		ASSERT_EXIT(item);

		/*
		 * Compare item->creds with cached creds of
		 * privileged one.
		 *
		 * cmd_info will always return cached creds.
		 */
		ASSERT_EXIT(item->creds.uid == cached_creds.uid &&
			    item->creds.gid == cached_creds.gid &&
			    item->creds.pid == cached_creds.pid &&
			    item->creds.tid == cached_creds.tid);

		kdbus_free(conn, offset);

		/*
		 * Use invalid_flags and make sure that userspace
		 * do not play with us.
		 */
		ret = kdbus_info(conn, conn->id, NULL,
				 invalid_flags, &offset);
		ASSERT_EXIT(ret == 0);

		/*
		 * Make sure that we return only one creds item and
		 * it points to the cached creds.
		 */
		cnt = kdbus_count_item(info, KDBUS_ITEM_CREDS);
		ASSERT_EXIT(cnt == 1);

		item = kdbus_get_item(info, KDBUS_ITEM_CREDS);
		ASSERT_EXIT(item);

		/* Compare item->creds with cached creds */
		ASSERT_EXIT(item->creds.uid == cached_creds.uid &&
			    item->creds.gid == cached_creds.gid &&
			    item->creds.pid == cached_creds.pid &&
			    item->creds.tid == cached_creds.tid);

		cnt = kdbus_count_item(info, KDBUS_ITEM_CGROUP);
		ASSERT_EXIT(cnt == 1);

		cnt = kdbus_count_item(info, KDBUS_ITEM_CAPS);
		ASSERT_EXIT(cnt == 1);

		kdbus_free(conn, offset);
	}),
	({ 0; }));

	/* A second name */
	ret = kdbus_name_acquire(conn, "com.example.b", NULL);
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_info(conn, conn->id, NULL, valid_flags, &offset);
	ASSERT_RETURN(ret == 0);

	info = (struct kdbus_info *)(conn->buf + offset);
	ASSERT_RETURN(info->id == conn->id);

	cnt = kdbus_count_item(info, KDBUS_ITEM_OWNED_NAME);
	ASSERT_RETURN(cnt == 2);

	kdbus_free(conn, offset);

	ASSERT_RETURN(ret == 0);

	return 0;
}

int kdbus_test_conn_info(struct kdbus_test_env *env)
{
	int ret;
	struct {
		struct kdbus_cmd_info cmd_info;

		struct {
			uint64_t size;
			uint64_t type;
			char str[64];
		} name;
	} buf;

	buf.cmd_info.size = sizeof(struct kdbus_cmd_info);
	buf.cmd_info.flags = 0;
	buf.cmd_info.id = env->conn->id;

	ret = kdbus_info(env->conn, env->conn->id, NULL, 0, NULL);
	ASSERT_RETURN(ret == 0);

	/* try to pass a name that is longer than the buffer's size */
	buf.name.size = KDBUS_ITEM_HEADER_SIZE + 1;
	buf.name.type = KDBUS_ITEM_NAME;
	strcpy(buf.name.str, "foo.bar.bla");

	buf.cmd_info.id = 0;
	buf.cmd_info.size = sizeof(buf.cmd_info) + buf.name.size;
	ret = ioctl(env->conn->fd, KDBUS_CMD_CONN_INFO, &buf);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	/* Pass a non existent name */
	ret = kdbus_info(env->conn, 0, "non.existent.name", 0, NULL);
	ASSERT_RETURN(ret == -ESRCH);

	/* Test for caps here, so we run the previous test */
	ret = test_is_capable(CAP_SETUID, CAP_SETGID, -1);
	ASSERT_RETURN(ret >= 0);

	if (!ret)
		return TEST_SKIP;

	ret = kdbus_fuzz_conn_info(env);
	ASSERT_RETURN(ret == 0);

	return TEST_OK;
}

int kdbus_test_conn_update(struct kdbus_test_env *env)
{
	const struct kdbus_item *item;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	int found = 0;
	int ret;

	/*
	 * kdbus_hello() sets all attach flags. Receive a message by this
	 * connection, and make sure a timestamp item (just to pick one) is
	 * present.
	 */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_msg_send(env->conn, NULL, 0x12345678, 0, 0, 0, conn->id);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == KDBUS_ITEM_TIMESTAMP)
			found = 1;

	kdbus_msg_free(msg);

	ASSERT_RETURN(found == 1);

	/*
	 * Now, modify the attach flags and repeat the action. The item must
	 * now be missing.
	 */
	found = 0;

	ret = kdbus_conn_update_attach_flags(conn, _KDBUS_ATTACH_ALL &
						   ~KDBUS_ATTACH_TIMESTAMP);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_send(env->conn, NULL, 0x12345678, 0, 0, 0, conn->id);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == KDBUS_ITEM_TIMESTAMP)
			found = 1;

	ASSERT_RETURN(found == 0);

	kdbus_msg_free(msg);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_writable_pool(struct kdbus_test_env *env)
{
	struct kdbus_cmd_hello hello;
	int fd, ret;
	void *map;

	fd = open(env->buspath, O_RDWR | O_CLOEXEC);
	ASSERT_RETURN(fd >= 0);

	memset(&hello, 0, sizeof(hello));
	hello.flags = KDBUS_HELLO_ACCEPT_FD;
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	hello.attach_flags_recv = _KDBUS_ATTACH_ALL;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;

	/* success test */
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == 0);

	/* pools cannot be mapped writable */
	map = mmap(NULL, POOL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ASSERT_RETURN(map == MAP_FAILED);

	/* pools can always be mapped readable */
	map = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	ASSERT_RETURN(map != MAP_FAILED);

	/* make sure we cannot change protection masks to writable */
	ret = mprotect(map, POOL_SIZE, PROT_READ | PROT_WRITE);
	ASSERT_RETURN(ret < 0);

	munmap(map, POOL_SIZE);
	close(fd);

	return TEST_OK;
}
