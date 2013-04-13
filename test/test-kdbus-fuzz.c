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

static int fd_table[100] = { -1 };

static void add_fd(int fd)
{
	unsigned int i;

	for (i = 0; i < ELEMENTSOF(fd_table); i++)
		if (fd_table[i] == -1)  {
			fd_table[i] = fd;
			return;
		}
}

static int make_bus(void)
{
	struct {
		struct kdbus_cmd_fname head;
		char name[64];
	} fname;
	char name[10];
	char *bus;
	unsigned int i;
	int ret, fdc;

	printf("-- opening /dev/kdbus/control\n");
	fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
	if (fdc < 0) {
		fprintf(stderr, "--- error %d (%m)\n", fdc);
		return EXIT_FAILURE;
	}

	add_fd(fdc);

	memset(name, 0, sizeof(name));

	for(i = 0; i < sizeof(name) - 1; i++)
		name[i] =( random() % ('z' - 'a')) + 'a';

	memset(&fname, 0, sizeof(fname));
	snprintf(fname.name, sizeof(fname.name), "%u-%s", getuid(), name);
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

	for (ret = 0; ret < random() % 20; ret++) {
		struct conn *conn = connect_to_bus(bus);
		if (conn)
			add_fd(conn->fd);
	}

	return 0;
}

static int get_random_fd(void)
{
	unsigned int i, count = 0;

	for (i = 0; i < ELEMENTSOF(fd_table); i++)
		if (fd_table[i] != -1)
			count++;

	count = random() % count;

	for (i = 0; i < ELEMENTSOF(fd_table); i++)
		if (fd_table[i] != -1)
			if (count-- == 0)
				return fd_table[i];

	return -1;
}

static void close_random_fd(void)
{
	unsigned int i, count = 0;

	for (i = 0; i < ELEMENTSOF(fd_table); i++)
		if (fd_table[i] != -1)
			count++;

	count = random() % count;

	for (i = 0; i < ELEMENTSOF(fd_table); i++)
		if (fd_table[i] != -1)
			if (count-- == 0) {
				close(fd_table[i]);
				fd_table[i] = -1;
				return;
			}
}

int main(int argc, char *argv[])
{
	unsigned int i;

	srandom(time(NULL));

	for (i = 0; i < ELEMENTSOF(fd_table); i++)
		fd_table[i] = -1;

	make_bus();
	make_bus();

	while(1) {
		char buf[0xffff];
		int fd = get_random_fd();
		int cmd = ioctl_cmds[random() % ELEMENTSOF(ioctl_cmds)];
		int ret;

		if (random() % 1000 == 0)
			make_bus();

		if (random() % 1000 == 0)
			close_random_fd();

		for (i = 0; i < sizeof(buf); i++)
			buf[i] = random();

		errno = 0;
		ret = ioctl(fd, cmd, buf);
		printf(" ioctl() with cmd %08x, on fd %d returned\t%d\t(%m)\n", cmd, fd, ret);
	}

	return EXIT_SUCCESS;
}
