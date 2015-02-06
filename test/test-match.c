#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

int kdbus_test_match_id_add(struct kdbus_test_env *env)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_notify_id_change chg;
		} item;
	} buf;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	int ret;

	memset(&buf, 0, sizeof(buf));

	buf.cmd.size = sizeof(buf);
	buf.cmd.cookie = 0xdeafbeefdeaddead;
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_ID_ADD;
	buf.item.chg.id = KDBUS_MATCH_ID_ANY;

	/* match on id add */
	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);
	ASSERT_RETURN(ret == 0);

	/* create 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* 1st connection should have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_ID_ADD);
	ASSERT_RETURN(msg->items[0].id_change.id == conn->id);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_match_id_remove(struct kdbus_test_env *env)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_notify_id_change chg;
		} item;
	} buf;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	size_t id;
	int ret;

	/* create 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);
	id = conn->id;

	memset(&buf, 0, sizeof(buf));
	buf.cmd.size = sizeof(buf);
	buf.cmd.cookie = 0xdeafbeefdeaddead;
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_ID_REMOVE;
	buf.item.chg.id = id;

	/* register match on 2nd connection */
	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);
	ASSERT_RETURN(ret == 0);

	/* remove 2nd connection again */
	kdbus_conn_free(conn);

	/* 1st connection should have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_ID_REMOVE);
	ASSERT_RETURN(msg->items[0].id_change.id == id);

	return TEST_OK;
}

int kdbus_test_match_replace(struct kdbus_test_env *env)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_notify_id_change chg;
		} item;
	} buf;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	size_t id;
	int ret;

	/* add a match to id_add */
	ASSERT_RETURN(kdbus_test_match_id_add(env) == TEST_OK);

	/* do a replace of the match from id_add to id_remove */
	memset(&buf, 0, sizeof(buf));

	buf.cmd.size = sizeof(buf);
	buf.cmd.cookie = 0xdeafbeefdeaddead;
	buf.cmd.flags = KDBUS_MATCH_REPLACE;
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_ID_REMOVE;
	buf.item.chg.id = KDBUS_MATCH_ID_ANY;

	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);

	/* create 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);
	id = conn->id;

	/* 1st connection should _not_ have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret != 0);

	/* remove 2nd connection */
	kdbus_conn_free(conn);

	/* 1st connection should _now_ have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_ID_REMOVE);
	ASSERT_RETURN(msg->items[0].id_change.id == id);

	return TEST_OK;
}

int kdbus_test_match_name_add(struct kdbus_test_env *env)
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
	struct kdbus_msg *msg;
	char *name;
	int ret;

	name = "foo.bla.blaz";

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.item.type = KDBUS_ITEM_NAME_ADD;
	buf.item.chg.old_id.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new_id.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.name, name, sizeof(buf.name) - 1);
	buf.item.size = sizeof(buf.item) + strlen(buf.name) + 1;
	buf.cmd.size = sizeof(buf.cmd) + buf.item.size;

	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);
	ASSERT_RETURN(ret == 0);

	/* acquire the name */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	/* we should have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_NAME_ADD);
	ASSERT_RETURN(msg->items[0].name_change.old_id.id == 0);
	ASSERT_RETURN(msg->items[0].name_change.new_id.id == env->conn->id);
	ASSERT_RETURN(strcmp(msg->items[0].name_change.name, name) == 0);

	return TEST_OK;
}

int kdbus_test_match_name_remove(struct kdbus_test_env *env)
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
	struct kdbus_msg *msg;
	char *name;
	int ret;

	name = "foo.bla.blaz";

	/* acquire the name */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.item.type = KDBUS_ITEM_NAME_REMOVE;
	buf.item.chg.old_id.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new_id.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.name, name, sizeof(buf.name) - 1);
	buf.item.size = sizeof(buf.item) + strlen(buf.name) + 1;
	buf.cmd.size = sizeof(buf.cmd) + buf.item.size;

	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);
	ASSERT_RETURN(ret == 0);

	/* release the name again */
	kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* we should have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_NAME_REMOVE);
	ASSERT_RETURN(msg->items[0].name_change.old_id.id == env->conn->id);
	ASSERT_RETURN(msg->items[0].name_change.new_id.id == 0);
	ASSERT_RETURN(strcmp(msg->items[0].name_change.name, name) == 0);

	return TEST_OK;
}

int kdbus_test_match_name_change(struct kdbus_test_env *env)
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
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	uint64_t flags;
	char *name = "foo.bla.baz";
	int ret;

	/* acquire the name */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.item.type = KDBUS_ITEM_NAME_CHANGE;
	buf.item.chg.old_id.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new_id.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.name, name, sizeof(buf.name) - 1);
	buf.item.size = sizeof(buf.item) + strlen(buf.name) + 1;
	buf.cmd.size = sizeof(buf.cmd) + buf.item.size;

	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);
	ASSERT_RETURN(ret == 0);

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	/* queue the 2nd connection as waiting owner */
	flags = KDBUS_NAME_QUEUE;
	ret = kdbus_name_acquire(conn, name, &flags);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(flags & KDBUS_NAME_IN_QUEUE);

	/* release name from 1st connection */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* we should have received a notification */
	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	ASSERT_RETURN(msg->items[0].type == KDBUS_ITEM_NAME_CHANGE);
	ASSERT_RETURN(msg->items[0].name_change.old_id.id == env->conn->id);
	ASSERT_RETURN(msg->items[0].name_change.new_id.id == conn->id);
	ASSERT_RETURN(strcmp(msg->items[0].name_change.name, name) == 0);

	kdbus_conn_free(conn);

	return TEST_OK;
}

static int send_bloom_filter(const struct kdbus_conn *conn,
			     uint64_t cookie,
			     const uint8_t *filter,
			     size_t filter_size,
			     uint64_t filter_generation)
{
	struct kdbus_cmd_send cmd = {};
	struct kdbus_msg *msg;
	struct kdbus_item *item;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + filter_size;

	msg = alloca(size);

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = KDBUS_DST_ID_BROADCAST;
	msg->flags = KDBUS_MSG_SIGNAL;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;
	msg->cookie = cookie;

	item = msg->items;
	item->type = KDBUS_ITEM_BLOOM_FILTER;
	item->size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) +
				filter_size;

	item->bloom_filter.generation = filter_generation;
	memcpy(item->bloom_filter.data, filter, filter_size);

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	ret = kdbus_cmd_send(conn->fd, &cmd);
	if (ret < 0) {
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	return 0;
}

int kdbus_test_match_bloom(struct kdbus_test_env *env)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct {
			uint64_t size;
			uint64_t type;
			uint8_t data_gen0[64];
			uint8_t data_gen1[64];
		} item;
	} buf;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	uint64_t cookie = 0xf000f00f;
	uint8_t filter[64];
	int ret;

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.cmd.size = sizeof(buf);

	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_BLOOM_MASK;
	buf.item.data_gen0[0] = 0x55;
	buf.item.data_gen0[63] = 0x80;

	buf.item.data_gen1[1] = 0xaa;
	buf.item.data_gen1[9] = 0x02;

	ret = kdbus_cmd_match_add(env->conn->fd, &buf.cmd);
	ASSERT_RETURN(ret == 0);

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* a message with a 0'ed out filter must not reach the other peer */
	memset(filter, 0, sizeof(filter));
	ret = send_bloom_filter(conn, ++cookie, filter, sizeof(filter), 0);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/* now set the filter to the connection's mask and expect success */
	filter[0] = 0x55;
	filter[63] = 0x80;
	ret = send_bloom_filter(conn, ++cookie, filter, sizeof(filter), 0);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	/* broaden the filter and try again. this should also succeed. */
	filter[0] = 0xff;
	filter[8] = 0xff;
	filter[63] = 0xff;
	ret = send_bloom_filter(conn, ++cookie, filter, sizeof(filter), 0);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	/* the same filter must not match against bloom generation 1 */
	ret = send_bloom_filter(conn, ++cookie, filter, sizeof(filter), 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/* set a different filter and try again */
	filter[1] = 0xaa;
	filter[9] = 0x02;
	ret = send_bloom_filter(conn, ++cookie, filter, sizeof(filter), 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(env->conn, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == cookie);

	kdbus_conn_free(conn);

	return TEST_OK;
}
