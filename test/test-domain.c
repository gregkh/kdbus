#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

int kdbus_test_domain_make(struct kdbus_test_env *env)
{
	int fd, fd2;
	struct {
		struct kdbus_cmd_make head;

		/* name item */
		uint64_t n_size;
		uint64_t n_type;
		char name[64];
	} domain_make;
	char s[PATH_MAX];
	int ret;

	snprintf(s, sizeof(s), "%s/control", env->root);
	fd = open(s, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(fd >= 0);

	memset(&domain_make, 0, sizeof(domain_make));

	domain_make.n_type = KDBUS_ITEM_MAKE_NAME;

	/* create a new domain */
	snprintf(domain_make.name, sizeof(domain_make.name), "blah");
	domain_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(domain_make.name) + 1;
	domain_make.head.size = sizeof(struct kdbus_cmd_make) + domain_make.n_size;
	domain_make.head.flags = 0;
	ret = ioctl(fd, KDBUS_CMD_DOMAIN_MAKE, &domain_make);
	if (ret < 0 && errno == EPERM)
		return TEST_SKIP;
	ASSERT_RETURN(ret == 0);

	snprintf(s, sizeof(s), "%s/domain/blah/control", env->root);
	ASSERT_RETURN(access(s, F_OK) == 0);

	/* can't use the same fd for domain make twice */
	ret = ioctl(fd, KDBUS_CMD_DOMAIN_MAKE, &domain_make);
	ASSERT_RETURN(ret == -1 && errno == EBADFD);

	/* can't register the same name twice */
	snprintf(s, sizeof(s), "%s/control", env->root);
	fd2 = open(s, O_RDWR|O_CLOEXEC);
	ret = ioctl(fd2, KDBUS_CMD_DOMAIN_MAKE, &domain_make);
	ASSERT_RETURN(ret == -1 && errno == EEXIST);
	close(fd2);

	close(fd);
	snprintf(s, sizeof(s), "%s/domain/blah/control", env->root);
	ASSERT_RETURN(access(s, F_OK) < 0);

	return TEST_OK;
}
