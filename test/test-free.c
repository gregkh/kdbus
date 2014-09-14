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
	uint64_t off = 0;

	/* free an unallocated buffer */
	ret = ioctl(env->conn->fd, KDBUS_CMD_FREE, &off);
	ASSERT_RETURN(ret == -1 && errno == ENXIO);

	/* free a buffer out of the pool's bounds */
	off = POOL_SIZE + 1;
	ret = ioctl(env->conn->fd, KDBUS_CMD_FREE, &off);
	ASSERT_RETURN(ret == -1 && errno == ENXIO);

	return TEST_OK;
}
