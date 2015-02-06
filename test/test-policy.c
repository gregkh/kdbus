#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

int kdbus_test_policy(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_a, *conn_b;
	struct kdbus_policy_access access;
	int ret;

	/* Invalid name */
	conn_a = kdbus_hello_registrar(env->buspath, ".example.a",
				       NULL, 0, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(conn_a == NULL);

	conn_a = kdbus_hello_registrar(env->buspath, "example",
				       NULL, 0, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(conn_a == NULL);

	conn_a = kdbus_hello_registrar(env->buspath, "com.example.a",
				       NULL, 0, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(conn_a);

	conn_b = kdbus_hello_registrar(env->buspath, "com.example.b",
				       NULL, 0, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(conn_b);

	/*
	 * Verify there cannot be any duplicate entries, except for specific vs.
	 * wildcard entries.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = geteuid(),
		.access = KDBUS_POLICY_SEE,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_update_policy(conn_b, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == -EEXIST);

	ret = kdbus_conn_update_policy(conn_b, "com.example.a.*", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_update_policy(conn_a, "com.example.a.*", &access, 1);
	ASSERT_RETURN(ret == -EEXIST);

	ret = kdbus_conn_update_policy(conn_a, "com.example.*", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_update_policy(conn_b, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_update_policy(conn_b, "com.example.*", &access, 1);
	ASSERT_RETURN(ret == -EEXIST);

	/* Invalid name */
	ret = kdbus_conn_update_policy(conn_b, ".example.*", &access, 1);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_conn_update_policy(conn_b, "example", &access, 1);
	ASSERT_RETURN(ret == -EINVAL);

	kdbus_conn_free(conn_b);
	kdbus_conn_free(conn_a);

	return TEST_OK;
}
