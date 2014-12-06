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

	ret = kdbus_sysfs_get_parameter_mask(env->mask_param_path,
					     &old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	asprintf(&s, "%s/control", env->root);

	control_fd = open(s, O_RDWR);
	free(s);
	ASSERT_RETURN(control_fd >= 0);

	busname = unique_name("test-attach-flags-bus");
	ASSERT_RETURN(busname);

	/* Restore previous kdbus mask */
	ret = kdbus_sysfs_set_parameter_mask(env->mask_param_path,
					     old_kdbus_flags_mask);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_sysfs_get_parameter_mask(env->mask_param_path,
					     &flags_mask);
	ASSERT_RETURN(old_kdbus_flags_mask == flags_mask);

	free(busname);
	close(control_fd);

	return TEST_OK;
}
