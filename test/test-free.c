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

	return TEST_OK;
}
