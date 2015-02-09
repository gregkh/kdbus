#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <getopt.h>
#include <stdbool.h>

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

static int conn_is_name_owner(const struct kdbus_conn *conn,
			      const char *needle)
{
	struct kdbus_cmd_list cmd_list = { .size = sizeof(cmd_list) };
	struct kdbus_info *name, *list;
	bool found = false;
	int ret;

	cmd_list.flags = KDBUS_LIST_NAMES;

	ret = kdbus_cmd_list(conn->fd, &cmd_list);
	ASSERT_RETURN(ret == 0);

	list = (struct kdbus_info *)(conn->buf + cmd_list.offset);
	KDBUS_FOREACH(name, list, cmd_list.list_size) {
		struct kdbus_item *item;
		const char *n = NULL;

		KDBUS_ITEM_FOREACH(item, name, items)
			if (item->type == KDBUS_ITEM_OWNED_NAME)
				n = item->name.name;

		if (name->id == conn->id &&
		    n && strcmp(needle, n) == 0) {
			found = true;
			break;
		}
	}

	ret = kdbus_free(conn, cmd_list.offset);
	ASSERT_RETURN(ret == 0);

	return found ? 0 : -1;
}

int kdbus_test_name_basic(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	char *name, *dot_name, *invalid_name, *wildcard_name;
	int ret;

	name = "foo.bla.blaz";
	dot_name = ".bla.blaz";
	invalid_name = "foo";
	wildcard_name = "foo.bla.bl.*";

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* acquire name "foo.bar.xxx" name */
	ret = kdbus_name_acquire(conn, "foo.bar.xxx", NULL);
	ASSERT_RETURN(ret == 0);

	/* Name is not valid, must fail */
	ret = kdbus_name_acquire(env->conn, dot_name, NULL);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_name_acquire(env->conn, invalid_name, NULL);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_name_acquire(env->conn, wildcard_name, NULL);
	ASSERT_RETURN(ret == -EINVAL);

	/* check that we can acquire a name */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* ... and release it again */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, name);
	ASSERT_RETURN(ret != 0);

	/* check that we can't release it again */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == -ESRCH);

	/* check that we can't release a name that we don't own */
	ret = kdbus_name_release(env->conn, "foo.bar.xxx");
	ASSERT_RETURN(ret == -EADDRINUSE);

	/* Name is not valid, must fail */
	ret = kdbus_name_release(env->conn, dot_name);
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_name_release(env->conn, invalid_name);
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_name_release(env->conn, wildcard_name);
	ASSERT_RETURN(ret == -ESRCH);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_name_conflict(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	char *name;
	int ret;

	name = "foo.bla.blaz";

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	/* acquire name from the 1st connection */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* check that we can't acquire it again from the 1st connection */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == -EALREADY);

	/* check that we also can't acquire it again from the 2nd connection */
	ret = kdbus_name_acquire(conn, name, NULL);
	ASSERT_RETURN(ret == -EEXIST);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_name_queue(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	const char *name;
	uint64_t flags;
	int ret;

	name = "foo.bla.blaz";

	flags = KDBUS_NAME_ALLOW_REPLACEMENT;

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	/* acquire name from the 1st connection */
	ret = kdbus_name_acquire(env->conn, name, &flags);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* queue the 2nd connection as waiting owner */
	flags = KDBUS_NAME_QUEUE;
	ret = kdbus_name_acquire(conn, name, &flags);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(flags & KDBUS_NAME_IN_QUEUE);

	/* release name from 1st connection */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* now the name should be owned by the 2nd connection */
	ret = conn_is_name_owner(conn, name);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);

	return TEST_OK;
}
