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
#include <poll.h>
#include <sys/ioctl.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"


int main(int argc, char *argv[])
{
	struct {
		struct kdbus_cmd_ns_make head;
		uint64_t n_size;
		uint64_t n_type;
		char name[64];
	} ns_make;
	int fd;
	char s[1];
	int ret;

	printf("Creating Namespace (press ENTER to exit)\n");

	fd = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "/dev/kdbus/control: %m\n");
		return EXIT_FAILURE;
	}

	memset(&ns_make, 0, sizeof(ns_make));
	ns_make.head.flags = KDBUS_MAKE_POLICY_OPEN;

	strcpy(ns_make.name, "test-ns");
	ns_make.n_type = KDBUS_MAKE_NAME;
	ns_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(ns_make.name) + 1;

	ns_make.head.size = sizeof(struct kdbus_cmd_ns_make) +
			    ns_make.n_size;

	ret = ioctl(fd, KDBUS_CMD_NS_MAKE, &ns_make);
	if (ret) {
		fprintf(stderr, "KDBUS_CMD_NS_MAKE: %m\n");
		return EXIT_FAILURE;
	}

	printf("Created Namespace '%s'\n", ns_make.name);
	read(STDIN_FILENO, &s, 1);
	printf("Closing Namespace\n");
	close(fd);

	return EXIT_SUCCESS;
}
