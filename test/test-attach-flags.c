#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static int kdbus_bus_creation_flags(struct kdbus_test_env *env)
{
	int ret;
	int control_fd;
	char *s;
	char *busname;
	uint64_t attach_flags_mask;

	asprintf(&s, "%s/control", env->root);

	control_fd = open(s, O_RDWR);
	free(s);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-creation-flags-bus");
	ASSERT_RETURN(busname);

	/* kdbus mask to 0 */
	attach_flags_mask = 0;
	ret = kdbus_sysfs_set_parameter_mask(attach_flags_mask);
	ASSERT_RETURN(ret == 0);

	/*
	 * Create bus with a full set of ATTACH flags, this must fail
	 * with -EINVAL
	 */

	ret = kdbus_create_bus(control_fd, busname, _KDBUS_ATTACH_ALL, &s);
	ASSERT_RETURN(ret == -EINVAL);

	/*
	 * Create bus with KDBUS_ATTACH_PIDS
	 */
	ret = kdbus_create_bus(control_fd, busname, KDBUS_ATTACH_PIDS, &s);
	ASSERT_RETURN(ret == -EINVAL);

	/* Update kdbus module attach flags mask */
	attach_flags_mask |= KDBUS_ATTACH_PIDS | KDBUS_ATTACH_CAPS;
	ret = kdbus_sysfs_set_parameter_mask(attach_flags_mask);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_create_bus(control_fd, busname,
			       KDBUS_ATTACH_PIDS |
			       KDBUS_ATTACH_CREDS, &s);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_create_bus(control_fd, busname, KDBUS_ATTACH_PIDS, &s);
	ASSERT_RETURN(ret == 0);

	free(s);
	free(busname);
	close(control_fd);

	return 0;
}

int kdbus_test_attach_flags(struct kdbus_test_env *env)
{
	int ret;
	int control_fd;
	char *s;
	char *busname;
	uint64_t flags_mask;
	uint64_t old_kdbus_flags_mask;

	/* We need CAP_DAC_OVERRIDE to overwrite the kdbus mask */
	ret = test_is_capable(CAP_DAC_OVERRIDE, -1);
	ASSERT_RETURN(ret >= 0);

	/* no enough privileges, SKIP test */
	if (!ret)
		return TEST_SKIP;

	ret = kdbus_sysfs_get_parameter_mask(&old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	asprintf(&s, "%s/control", env->root);

	control_fd = open(s, O_RDWR);
	free(s);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-attach-flags-bus");
	ASSERT_RETURN(busname);

	/* Test bus creation */
	ret = kdbus_bus_creation_flags(env);
	ASSERT_RETURN(ret == 0);

	/* Restore previous kdbus mask */
	ret = kdbus_sysfs_set_parameter_mask(old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_sysfs_get_parameter_mask(&flags_mask);
	ASSERT_RETURN(old_kdbus_flags_mask == flags_mask);

	free(busname);
	close(control_fd);

	return TEST_OK;
}
