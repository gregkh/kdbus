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

static int sample_ioctl_call(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_cmd_list cmd_list = {
		.flags = KDBUS_LIST_QUEUED,
		.size = sizeof(cmd_list),
	};

	ret = kdbus_cmd_list(env->conn->fd, &cmd_list);
	ASSERT_RETURN(ret == 0);

	/* DON'T FREE THIS SLICE OF MEMORY! */

	return TEST_OK;
}

int kdbus_test_free(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_cmd_free cmd_free = {};

	/* free an unallocated buffer */
	cmd_free.size = sizeof(cmd_free);
	cmd_free.flags = 0;
	cmd_free.offset = 0;
	ret = kdbus_cmd_free(env->conn->fd, &cmd_free);
	ASSERT_RETURN(ret == -ENXIO);

	/* free a buffer out of the pool's bounds */
	cmd_free.size = sizeof(cmd_free);
	cmd_free.offset = POOL_SIZE + 1;
	ret = kdbus_cmd_free(env->conn->fd, &cmd_free);
	ASSERT_RETURN(ret == -ENXIO);

	/*
	 * The user application is responsible for freeing the allocated
	 * memory with the KDBUS_CMD_FREE ioctl, so let's test what happens
	 * if we forget about it.
	 */

	ret = sample_ioctl_call(env);
	ASSERT_RETURN(ret == 0);

	ret = sample_ioctl_call(env);
	ASSERT_RETURN(ret == 0);

	return TEST_OK;
}
