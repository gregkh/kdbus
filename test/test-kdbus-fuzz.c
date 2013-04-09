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

//#include "include/uapi/kdbus/kdbus.h"
#include "../kdbus.h"

#include "kdbus-util.h"
#include "kdbus-enum.h"

static unsigned int ioctl_cmds[] = {
	KDBUS_CMD_BUS_MAKE,
	KDBUS_CMD_NS_MAKE,
	KDBUS_CMD_BUS_POLICY_SET,
	KDBUS_CMD_EP_MAKE,
	KDBUS_CMD_HELLO,
	KDBUS_CMD_MSG_SEND,
	KDBUS_CMD_MSG_RECV,
	KDBUS_CMD_NAME_ACQUIRE,
	KDBUS_CMD_NAME_RELEASE,
	KDBUS_CMD_NAME_LIST,
	KDBUS_CMD_NAME_QUERY,
	KDBUS_CMD_MATCH_ADD,
	KDBUS_CMD_MATCH_REMOVE,
	KDBUS_CMD_MONITOR,
	KDBUS_CMD_EP_POLICY_SET,
};

int main(int argc, char *argv[])
{
	struct {
		struct kdbus_cmd_fname head;
		char name[64];
	} fname;
	char *bus;
	struct conn *conn_a, *conn_b;
	int ret, fdc;

	printf("-- opening /dev/kdbus/control\n");
	fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
	if (fdc < 0) {
		fprintf(stderr, "--- error %d (%m)\n", fdc);
		return EXIT_FAILURE;
	}

	memset(&fname, 0, sizeof(fname));
	snprintf(fname.name, sizeof(fname.name), "%u-testbus", getuid());
	fname.head.flags = KDBUS_CMD_FNAME_ACCESS_WORLD;
	fname.head.size = sizeof(struct kdbus_cmd_fname) + strlen(fname.name) + 1;

	printf("-- creating bus '%s'\n", fname.name);
	ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &fname);
	if (ret) {
		fprintf(stderr, "--- error %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	if (asprintf(&bus, "/dev/kdbus/%s/bus", fname.name) < 0)
		return EXIT_FAILURE;

	conn_a = connect_to_bus(bus);
	conn_b = connect_to_bus(bus);
	if (!conn_a || !conn_b)
		return EXIT_FAILURE;

	while(1) {
		int i;
		char buf[0xffff];
		int fds[] = { fdc, conn_a->fd, conn_b->fd };
		int fd = fds[random() % ELEMENTSOF(fds)];
		int cmd = ioctl_cmds[random() % ELEMENTSOF(ioctl_cmds)];

		for (i = 0; i < sizeof(buf); i++)
			buf[i] = random();

		printf(" calling ioctl(), cmd %016x, fd %d\n", cmd, fd);
		ioctl(fd, cmd, buf);
	}

	return EXIT_SUCCESS;
}
