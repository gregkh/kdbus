#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

/* maximum number of queued messages from the same individual user */
#define KDBUS_CONN_MAX_MSGS			256

/* maximum number of queued requests waiting for a reply */
#define KDBUS_CONN_MAX_REQUESTS_PENDING		128

/* maximum message payload size */
#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE		(2 * 1024UL * 1024UL)

int kdbus_test_message_basic(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct kdbus_conn *sender;
	struct kdbus_msg *msg;
	uint64_t cookie = 0x1234abcd5678eeff;
	uint64_t offset;
	int ret;

	sender = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(sender != NULL);

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	ret = kdbus_add_match_empty(conn);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(sender);
	ASSERT_RETURN(ret == 0);

	/* send over 1st connection */
	ret = kdbus_msg_send(sender, NULL, cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* Make sure that we do not get our own broadcasts */
	ret = kdbus_msg_recv(sender, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/* ... and receive on the 2nd */
	ret = kdbus_msg_recv_poll(conn, 100, &msg, &offset);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_msg_free(msg);

	/* Msgs that expect a reply must have timeout and cookie */
	ret = kdbus_msg_send(sender, NULL, 0, KDBUS_MSG_EXPECT_REPLY,
			     0, 0, conn->id);
	ASSERT_RETURN(ret == -EINVAL);

	/* Faked replies with a valid reply cookie are rejected */
	ret = kdbus_msg_send_reply(conn, time(NULL) ^ cookie, sender->id);
	ASSERT_RETURN(ret == -EPERM);

	ret = kdbus_free(conn, offset);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(sender);
	kdbus_conn_free(conn);

	return TEST_OK;
}

static int msg_recv_prio(struct kdbus_conn *conn,
			 int64_t requested_prio,
			 int64_t expected_prio)
{
	struct kdbus_cmd_recv recv = {
		.size = sizeof(recv),
		.flags = KDBUS_RECV_USE_PRIORITY,
		.priority = requested_prio,
	};
	struct kdbus_msg *msg;
	int ret;

	ret = kdbus_cmd_recv(conn->fd, &recv);
	if (ret < 0) {
		kdbus_printf("error receiving message: %d (%m)\n", -errno);
		return ret;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.msg.offset);
	kdbus_msg_dump(conn, msg);

	if (msg->priority != expected_prio) {
		kdbus_printf("expected message prio %lld, got %lld\n",
			     (unsigned long long) expected_prio,
			     (unsigned long long) msg->priority);
		return -EINVAL;
	}

	kdbus_msg_free(msg);
	ret = kdbus_free(conn, recv.msg.offset);
	if (ret < 0)
		return ret;

	return 0;
}

int kdbus_test_message_prio(struct kdbus_test_env *env)
{
	struct kdbus_conn *a, *b;
	uint64_t cookie = 0;

	a = kdbus_hello(env->buspath, 0, NULL, 0);
	b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(a && b);

	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   25, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -600, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   10, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,  -35, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -100, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   20, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,  -15, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -800, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -150, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,   10, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0, -800, a->id) == 0);
	ASSERT_RETURN(kdbus_msg_send(b, NULL, ++cookie, 0, 0,  -10, a->id) == 0);

	ASSERT_RETURN(msg_recv_prio(a, -200, -800) == 0);
	ASSERT_RETURN(msg_recv_prio(a, -100, -800) == 0);
	ASSERT_RETURN(msg_recv_prio(a, -400, -600) == 0);
	ASSERT_RETURN(msg_recv_prio(a, -400, -600) == -EAGAIN);
	ASSERT_RETURN(msg_recv_prio(a, 10, -150) == 0);
	ASSERT_RETURN(msg_recv_prio(a, 10, -100) == 0);

	kdbus_printf("--- get priority (all)\n");
	ASSERT_RETURN(kdbus_msg_recv(a, NULL, NULL) == 0);

	kdbus_conn_free(a);
	kdbus_conn_free(b);

	return TEST_OK;
}

static int kdbus_test_notify_kernel_quota(struct kdbus_test_env *env)
{
	int ret;
	unsigned int i;
	struct kdbus_conn *conn;
	struct kdbus_conn *reader;
	struct kdbus_msg *msg = NULL;
	struct kdbus_cmd_recv recv = { .size = sizeof(recv) };

	reader = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(reader);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	/* Register for ID signals */
	ret = kdbus_add_match_id(reader, 0x1, KDBUS_ITEM_ID_ADD,
				 KDBUS_MATCH_ID_ANY);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_id(reader, 0x2, KDBUS_ITEM_ID_REMOVE,
				 KDBUS_MATCH_ID_ANY);
	ASSERT_RETURN(ret == 0);

	/* Each iteration two notifications: add and remove ID */
	for (i = 0; i < KDBUS_CONN_MAX_MSGS / 2; i++) {
		struct kdbus_conn *notifier;

		notifier = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(notifier);

		kdbus_conn_free(notifier);
	}

	/*
	 * Now the reader queue is full with kernel notfications,
	 * but as a user we still have room to push our messages.
	 */
	ret = kdbus_msg_send(conn, NULL, 0xdeadbeef, 0, 0, 0, reader->id);
	ASSERT_RETURN(ret == 0);

	/* More ID kernel notifications that will be lost */
	kdbus_conn_free(conn);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	kdbus_conn_free(conn);

	/*
	 * We lost only 3 packets since only signal msgs are
	 * accounted. The connection ID add/remove notification
	 */
	ret = kdbus_cmd_recv(reader->fd, &recv);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(recv.return_flags & KDBUS_RECV_RETURN_DROPPED_MSGS);
	ASSERT_RETURN(recv.dropped_msgs == 3);

	msg = (struct kdbus_msg *)(reader->buf + recv.msg.offset);
	kdbus_msg_free(msg);

	/* Read our queue */
	for (i = 0; i < KDBUS_CONN_MAX_MSGS - 1; i++) {
		memset(&recv, 0, sizeof(recv));
		recv.size = sizeof(recv);

		ret = kdbus_cmd_recv(reader->fd, &recv);
		ASSERT_RETURN(ret == 0);
		ASSERT_RETURN(!(recv.return_flags &
			        KDBUS_RECV_RETURN_DROPPED_MSGS));

		msg = (struct kdbus_msg *)(reader->buf + recv.msg.offset);
		kdbus_msg_free(msg);
	}

	ret = kdbus_msg_recv(reader, NULL, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(reader, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	kdbus_conn_free(reader);

	return 0;
}

/* Return the number of message successfully sent */
static int kdbus_fill_conn_queue(struct kdbus_conn *conn_src,
				 uint64_t dst_id,
				 unsigned int max_msgs)
{
	unsigned int i;
	uint64_t cookie = 0;
	size_t size;
	struct kdbus_cmd_send cmd = {};
	struct kdbus_msg *msg;
	int ret;

	size = sizeof(struct kdbus_msg);
	msg = malloc(size);
	ASSERT_RETURN_VAL(msg, -ENOMEM);

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn_src->id;
	msg->dst_id = dst_id;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	for (i = 0; i < max_msgs; i++) {
		msg->cookie = cookie++;
		ret = kdbus_cmd_send(conn_src->fd, &cmd);
		if (ret < 0)
			break;
	}

	free(msg);

	return i;
}

static int kdbus_test_activator_quota(struct kdbus_test_env *env)
{
	int ret;
	unsigned int i;
	unsigned int activator_msgs_count = 0;
	uint64_t cookie = time(NULL);
	struct kdbus_conn *conn;
	struct kdbus_conn *sender;
	struct kdbus_conn *activator;
	struct kdbus_msg *msg;
	uint64_t flags = KDBUS_NAME_REPLACE_EXISTING;
	struct kdbus_cmd_recv recv = { .size = sizeof(recv) };
	struct kdbus_policy_access access = {
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = geteuid(),
		.access = KDBUS_POLICY_OWN,
	};

	activator = kdbus_hello_activator(env->buspath, "foo.test.activator",
					  &access, 1);
	ASSERT_RETURN(activator);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	sender = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn || sender);

	ret = kdbus_list(sender, KDBUS_LIST_NAMES |
				 KDBUS_LIST_UNIQUE |
				 KDBUS_LIST_ACTIVATORS |
				 KDBUS_LIST_QUEUED);
	ASSERT_RETURN(ret == 0);

	for (i = 0; i < KDBUS_CONN_MAX_MSGS; i++) {
		ret = kdbus_msg_send(sender, "foo.test.activator",
				     cookie++, 0, 0, 0,
				     KDBUS_DST_ID_NAME);
		if (ret < 0)
			break;
		activator_msgs_count++;
	}

	/* we must have at least sent one message */
	ASSERT_RETURN_VAL(i > 0, -errno);
	ASSERT_RETURN(ret == -ENOBUFS);

	/* Good, activator queue is full now */

	/* ENXIO on direct send (activators can never be addressed by ID) */
	ret = kdbus_msg_send(conn, NULL, cookie++, 0, 0, 0, activator->id);
	ASSERT_RETURN(ret == -ENXIO);

	/* can't queue more */
	ret = kdbus_msg_send(conn, "foo.test.activator", cookie++,
			     0, 0, 0, KDBUS_DST_ID_NAME);
	ASSERT_RETURN(ret == -ENOBUFS);

	/* no match installed, so the broadcast will not inc dropped_msgs */
	ret = kdbus_msg_send(sender, NULL, cookie++, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	/* Check activator queue */
	ret = kdbus_cmd_recv(activator->fd, &recv);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(recv.dropped_msgs == 0);

	activator_msgs_count--;

	msg = (struct kdbus_msg *)(activator->buf + recv.msg.offset);
	kdbus_msg_free(msg);


	/* Stage 1) of test check the pool memory quota */

	/* Consume the connection pool memory */
	for (i = 0; i < KDBUS_CONN_MAX_MSGS; i++) {
		ret = kdbus_msg_send(sender, NULL,
				     cookie++, 0, 0, 0, conn->id);
		if (ret < 0)
			break;
	}

	/* consume one message, so later at least one can be moved */
	memset(&recv, 0, sizeof(recv));
	recv.size = sizeof(recv);
	ret = kdbus_cmd_recv(conn->fd, &recv);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(recv.dropped_msgs == 0);
	msg = (struct kdbus_msg *)(conn->buf + recv.msg.offset);
	kdbus_msg_free(msg);

	/* Try to acquire the name now */
	ret = kdbus_name_acquire(conn, "foo.test.activator", &flags);
	ASSERT_RETURN(ret == 0);

	/* try to read messages and see if we have lost some */
	memset(&recv, 0, sizeof(recv));
	recv.size = sizeof(recv);
	ret = kdbus_cmd_recv(conn->fd, &recv);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(recv.dropped_msgs != 0);

	/* number of dropped msgs < received ones (at least one was moved) */
	ASSERT_RETURN(recv.dropped_msgs < activator_msgs_count);

	/* Deduct the number of dropped msgs from the activator msgs */
	activator_msgs_count -= recv.dropped_msgs;

	msg = (struct kdbus_msg *)(activator->buf + recv.msg.offset);
	kdbus_msg_free(msg);

	/*
	 * Release the name and hand it back to activator, now
	 * we should have 'activator_msgs_count' msgs again in
	 * the activator queue
	 */
	ret = kdbus_name_release(conn, "foo.test.activator");
	ASSERT_RETURN(ret == 0);

	/* make sure that we got our previous activator msgs */
	ret = kdbus_msg_recv(activator, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->src_id == sender->id);

	activator_msgs_count--;

	kdbus_msg_free(msg);


	/* Stage 2) of test check max message quota */

	/* Empty conn queue */
	for (i = 0; i < KDBUS_CONN_MAX_MSGS; i++) {
		ret = kdbus_msg_recv(conn, NULL, NULL);
		if (ret == -EAGAIN)
			break;
	}

	/* fill queue with max msgs quota */
	ret = kdbus_fill_conn_queue(sender, conn->id, KDBUS_CONN_MAX_MSGS);
	ASSERT_RETURN(ret == KDBUS_CONN_MAX_MSGS);

	/* This one is lost but it is not accounted */
	ret = kdbus_msg_send(sender, NULL,
			     cookie++, 0, 0, 0, conn->id);
	ASSERT_RETURN(ret == -ENOBUFS);

	/* Acquire the name again */
	ret = kdbus_name_acquire(conn, "foo.test.activator", &flags);
	ASSERT_RETURN(ret == 0);

	memset(&recv, 0, sizeof(recv));
	recv.size = sizeof(recv);

	/*
	 * Try to read messages and make sure that we have lost all
	 * the activator messages due to quota checks. Our queue is
	 * already full.
	 */
	ret = kdbus_cmd_recv(conn->fd, &recv);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(recv.dropped_msgs == activator_msgs_count);

	msg = (struct kdbus_msg *)(activator->buf + recv.msg.offset);
	kdbus_msg_free(msg);

	kdbus_conn_free(sender);
	kdbus_conn_free(conn);
	kdbus_conn_free(activator);

	return 0;
}

static int kdbus_test_expected_reply_quota(struct kdbus_test_env *env)
{
	int ret;
	unsigned int i, n;
	unsigned int count;
	uint64_t cookie = 0x1234abcd5678eeff;
	struct kdbus_conn *conn;
	struct kdbus_conn *connections[9];

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	for (i = 0; i < 9; i++) {
		connections[i] = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(connections[i]);
	}

	count = 0;
	/* Send 16 messages to 8 different connections */
	for (i = 0; i < 8; i++) {
		for (n = 0; n < 16; n++) {
			ret = kdbus_msg_send(conn, NULL, cookie++,
					     KDBUS_MSG_EXPECT_REPLY,
					     100000000ULL, 0,
					     connections[i]->id);
			if (ret < 0)
				break;

			count++;
		}
	}

	/*
	 * We should have queued at least
	 * KDBUS_CONN_MAX_REQUESTS_PENDING method call
	 */
	ASSERT_RETURN(count == KDBUS_CONN_MAX_REQUESTS_PENDING);

	/*
	 * Now try to send a message to the last connection,
	 * if we have reached KDBUS_CONN_MAX_REQUESTS_PENDING
	 * no further requests are allowed
	 */
	ret = kdbus_msg_send(conn, NULL, cookie++, KDBUS_MSG_EXPECT_REPLY,
			     1000000000ULL, 0, connections[8]->id);
	ASSERT_RETURN(ret == -EMLINK);

	for (i = 0; i < 9; i++)
		kdbus_conn_free(connections[i]);

	kdbus_conn_free(conn);

	return 0;
}

int kdbus_test_pool_quota(struct kdbus_test_env *env)
{
	struct kdbus_conn *a, *b, *c;
	struct kdbus_cmd_send cmd = {};
	struct kdbus_item *item;
	struct kdbus_msg *recv_msg;
	struct kdbus_msg *msg;
	uint64_t cookie = time(NULL);
	uint64_t size;
	unsigned int i;
	char *payload;
	int ret;

	/* just a guard */
	if (POOL_SIZE <= KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE ||
	    POOL_SIZE % KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE != 0)
		return 0;

	payload = calloc(KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE, sizeof(char));
	ASSERT_RETURN_VAL(payload, -ENOMEM);

	a = kdbus_hello(env->buspath, 0, NULL, 0);
	b = kdbus_hello(env->buspath, 0, NULL, 0);
	c = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(a && b && c);

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	msg = malloc(size);
	ASSERT_RETURN_VAL(msg, -ENOMEM);

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = a->id;
	msg->dst_id = c->id;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	item = msg->items;
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)payload;
	item->vec.size = KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
	item = KDBUS_ITEM_NEXT(item);

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	/*
	 * Send 2097248 bytes, a user is only allowed to get 33% of half of
	 * the free space of the pool, the already used space is
	 * accounted as free space
	 */
	size += KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
	for (i = size; i < (POOL_SIZE / 2 / 3); i += size) {
		msg->cookie = cookie++;

		ret = kdbus_cmd_send(a->fd, &cmd);
		ASSERT_RETURN_VAL(ret == 0, ret);
	}

	/* Try to get more than 33% */
	msg->cookie = cookie++;
	ret = kdbus_cmd_send(a->fd, &cmd);
	ASSERT_RETURN(ret == -ENOBUFS);

	/* We still can pass small messages */
	ret = kdbus_msg_send(b, NULL, cookie++, 0, 0, 0, c->id);
	ASSERT_RETURN(ret == 0);

	for (i = size; i < (POOL_SIZE / 2 / 3); i += size) {
		ret = kdbus_msg_recv(c, &recv_msg, NULL);
		ASSERT_RETURN(ret == 0);
		ASSERT_RETURN(recv_msg->src_id == a->id);

		kdbus_msg_free(recv_msg);
	}

	ret = kdbus_msg_recv(c, &recv_msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(recv_msg->src_id == b->id);

	kdbus_msg_free(recv_msg);

	ret = kdbus_msg_recv(c, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	free(msg);
	free(payload);

	kdbus_conn_free(c);
	kdbus_conn_free(b);
	kdbus_conn_free(a);

	return 0;
}

int kdbus_test_message_quota(struct kdbus_test_env *env)
{
	struct kdbus_conn *a, *b;
	uint64_t cookie = 0;
	int ret;
	int i;

	ret = kdbus_test_activator_quota(env);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_test_notify_kernel_quota(env);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_test_pool_quota(env);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_test_expected_reply_quota(env);
	ASSERT_RETURN(ret == 0);

	a = kdbus_hello(env->buspath, 0, NULL, 0);
	b = kdbus_hello(env->buspath, 0, NULL, 0);

	ret = kdbus_fill_conn_queue(b, a->id, KDBUS_CONN_MAX_MSGS);
	ASSERT_RETURN(ret == KDBUS_CONN_MAX_MSGS);

	ret = kdbus_msg_send(b, NULL, ++cookie, 0, 0, 0, a->id);
	ASSERT_RETURN(ret == -ENOBUFS);

	for (i = 0; i < KDBUS_CONN_MAX_MSGS; ++i) {
		ret = kdbus_msg_recv(a, NULL, NULL);
		ASSERT_RETURN(ret == 0);
	}

	ret = kdbus_msg_recv(a, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	ret = kdbus_fill_conn_queue(b, a->id, KDBUS_CONN_MAX_MSGS + 1);
	ASSERT_RETURN(ret == KDBUS_CONN_MAX_MSGS);

	ret = kdbus_msg_send(b, NULL, ++cookie, 0, 0, 0, a->id);
	ASSERT_RETURN(ret == -ENOBUFS);

	kdbus_conn_free(a);
	kdbus_conn_free(b);

	return TEST_OK;
}

int kdbus_test_memory_access(struct kdbus_test_env *env)
{
	struct kdbus_conn *a, *b;
	struct kdbus_cmd_send cmd = {};
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t test_addr = 0;
	char line[256];
	uint64_t size;
	FILE *f;
	int ret;

	/*
	 * Search in /proc/kallsyms for the address of a kernel symbol that
	 * should always be there, regardless of the config. Use that address
	 * in a PAYLOAD_VEC item and make sure it's inaccessible.
	 */

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return TEST_SKIP;

	while (fgets(line, sizeof(line), f)) {
		char *s = line;

		if (!strsep(&s, " "))
			continue;

		if (!strsep(&s, " "))
			continue;

		if (!strncmp(s, "mutex_lock", 10)) {
			test_addr = strtoull(line, NULL, 16);
			break;
		}
	}

	fclose(f);

	if (!test_addr)
		return TEST_SKIP;

	a = kdbus_hello(env->buspath, 0, NULL, 0);
	b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(a && b);

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	msg = alloca(size);
	ASSERT_RETURN_VAL(msg, -ENOMEM);

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = a->id;
	msg->dst_id = b->id;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	item = msg->items;
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = test_addr;
	item->vec.size = sizeof(void*);
	item = KDBUS_ITEM_NEXT(item);

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	ret = kdbus_cmd_send(a->fd, &cmd);
	ASSERT_RETURN(ret == -EFAULT);

	kdbus_conn_free(b);
	kdbus_conn_free(a);

	return 0;
}
