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

int kdbus_test_free(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_cmd_free cmd_free;

	/* free an unallocated buffer */
	cmd_free.flags = 0;
	cmd_free.offset = 0;
	ret = ioctl(env->conn->fd, KDBUS_CMD_FREE, &cmd_free);
	ASSERT_RETURN(ret == -1 && errno == ENXIO);

	/* free a buffer out of the pool's bounds */
	cmd_free.offset = POOL_SIZE + 1;
	ret = ioctl(env->conn->fd, KDBUS_CMD_FREE, &cmd_free);
	ASSERT_RETURN(ret == -1 && errno == ENXIO);

	return TEST_OK;
}
