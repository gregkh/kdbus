#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <stdbool.h>

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
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	struct kdbus_cmd_recv recv = {};
	int ret;

	memset(&buf, 0, sizeof(buf));

	buf.cmd.size = sizeof(buf);
	buf.cmd.cookie = 0xdeafbeefdeaddead;
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_ID_ADD;
	buf.item.chg.id = KDBUS_MATCH_ID_ANY;

	/* match on id add */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MATCH_ADD, &buf);
	ASSERT_RETURN(ret == 0);

	/* create 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* 1st connection should have received a notification */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	msg = (struct kdbus_msg *)(env->conn->buf + recv.offset);
	item = &msg->items[0];
	ASSERT_RETURN(item->type == KDBUS_ITEM_ID_ADD);
	ASSERT_RETURN(item->id_change.id == conn->id);

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
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	struct kdbus_cmd_recv recv = {};
	size_t id;
	int ret;

	/* create 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	id = conn->id;
	ASSERT_RETURN(conn != NULL);

	memset(&buf, 0, sizeof(buf));
	buf.cmd.size = sizeof(buf);
	buf.cmd.cookie = 0xdeafbeefdeaddead;
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_ID_REMOVE;
	buf.item.chg.id = id;

	/* register match on 2nd connection */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MATCH_ADD, &buf);
	ASSERT_RETURN(ret == 0);

	/* remove 2nd connection again */
	kdbus_conn_free(conn);

	/* 1st connection should have received a notification */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	msg = (struct kdbus_msg *)(env->conn->buf + recv.offset);
	item = &msg->items[0];
	ASSERT_RETURN(item->type == KDBUS_ITEM_ID_REMOVE);
	ASSERT_RETURN(item->id_change.id == id);

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
			char name[64];
		} item;
	} buf;
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	struct kdbus_cmd_recv recv = {};
	char *name;
	int ret;

	name = "foo.bla.blaz";

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.cmd.size = sizeof(buf);
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_NAME_ADD;
	buf.item.chg.old.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.item.name, name, sizeof(buf.item.name));

	ret = ioctl(env->conn->fd, KDBUS_CMD_MATCH_ADD, &buf);
	ASSERT_RETURN(ret == 0);

	/* acquire the name */
	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = 0;
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	/* we should have received a notification */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	msg = (struct kdbus_msg *)(env->conn->buf + recv.offset);
	item = &msg->items[0];
	ASSERT_RETURN(item->type == KDBUS_ITEM_NAME_ADD);
	ASSERT_RETURN(item->name_change.old.id == 0);
	ASSERT_RETURN(item->name_change.new.id == env->conn->id);
	ASSERT_RETURN(strcmp(item->name_change.name, name) == 0);

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
			char name[64];
		} item;
	} buf;
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	uint64_t size;
	struct kdbus_cmd_recv recv = {};
	char *name;
	int ret;

	name = "foo.bla.blaz";

	/* acquire the name */
	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = 0;
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.cmd.size = sizeof(buf);
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_NAME_REMOVE;
	buf.item.chg.old.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.item.name, name, sizeof(buf.item.name));

	ret = ioctl(env->conn->fd, KDBUS_CMD_MATCH_ADD, &buf);
	ASSERT_RETURN(ret == 0);

	/* release the name again */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	ASSERT_RETURN(ret == 0);

	/* we should have received a notification */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	msg = (struct kdbus_msg *)(env->conn->buf + recv.offset);
	item = &msg->items[0];
	ASSERT_RETURN(item->type == KDBUS_ITEM_NAME_REMOVE);
	ASSERT_RETURN(item->name_change.old.id == env->conn->id);
	ASSERT_RETURN(item->name_change.new.id == 0);
	ASSERT_RETURN(strcmp(item->name_change.name, name) == 0);

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
			char name[64];
		} item;
	} buf;
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_item *item;
	struct kdbus_conn *conn;
	struct kdbus_msg *msg;
	uint64_t size;
	struct kdbus_cmd_recv recv = {};
	char *name;
	int ret;

	/* acquire the name */
	name = "foo.bla.blaz";
	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = KDBUS_NAME_ALLOW_REPLACEMENT;
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	/* install the match rule */
	memset(&buf, 0, sizeof(buf));
	buf.cmd.size = sizeof(buf);
	buf.item.size = sizeof(buf.item);
	buf.item.type = KDBUS_ITEM_NAME_CHANGE;
	buf.item.chg.old.id = KDBUS_MATCH_ID_ANY;
	buf.item.chg.new.id = KDBUS_MATCH_ID_ANY;
	strncpy(buf.item.name, name, sizeof(buf.item.name));

	ret = ioctl(env->conn->fd, KDBUS_CMD_MATCH_ADD, &buf);
	ASSERT_RETURN(ret == 0);

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	/* queue the 2nd connection as waiting owner */
	cmd_name->flags = KDBUS_NAME_QUEUE;
	ret = ioctl(conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(cmd_name->flags & KDBUS_NAME_IN_QUEUE);

	/* release name from 1st connection */
	cmd_name->flags = 0;
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	ASSERT_RETURN(ret == 0);

	/* we should have received a notification */
	ret = ioctl(env->conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	ASSERT_RETURN(ret == 0);

	msg = (struct kdbus_msg *)(env->conn->buf + recv.offset);
	item = &msg->items[0];
	ASSERT_RETURN(item->type == KDBUS_ITEM_NAME_CHANGE);
	ASSERT_RETURN(item->name_change.old.id == env->conn->id);
	ASSERT_RETURN(item->name_change.new.id == conn->id);
	ASSERT_RETURN(strcmp(item->name_change.name, name) == 0);

	kdbus_conn_free(conn);

	return TEST_OK;
}
