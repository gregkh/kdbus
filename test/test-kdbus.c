#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>

//#include "include/uapi/kdbus/kdbus.h"
#include "../kdbus.h"

static int connect_to_bus(const char *path)
{
	int fd, err;
	struct kdbus_cmd_hello hello;

	printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "--- error %d (\"%s\")\n", fd, strerror(errno));
		return EXIT_FAILURE;
	}

	memset(&hello, 0, sizeof(hello));
	err = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	if (err) {
		fprintf(stderr, "--- error when saying hello: %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}
	printf("-- Our peer ID for %s: %lu\n", path, (uint64_t)hello.id);

	return fd;
}

int main(int argc, char *argv[])
{
	struct kdbus_cmd_fname name;
	int fdc, fdb, err;
	char *busname, *bus;
	uid_t uid;

	memset(&name, 0, sizeof(name));

	uid = getuid();
	if (argv[1])
		busname = argv[1];
	else if (uid > 0)
		busname = "system";
	else
		busname = "user";
	strncpy(name.name, busname, sizeof(name.name));

	printf("-- opening /dev/kdbus/control\n");
	fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
	if (fdc < 0) {
		fprintf(stderr, "--- error %d (\"%s\")\n", fdc, strerror(fdc));
		return EXIT_FAILURE;
	}

	snprintf(name.name, sizeof(name.name), "%u-testbus", uid);

	printf("-- creating bus '%s'\n", name.name);
	err = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &name);
	if (err) {
		fprintf(stderr, "--- error %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}

	asprintf(&bus, "/dev/kdbus/%s/bus", name.name);

	fdb = connect_to_bus(bus);

	printf("-- sleeping 10s\n");
	sleep(10);

	printf("-- closing bus connection\n");
	close(fdb);

	printf("-- closing bus master\n");
	close(fdc);

	return EXIT_SUCCESS;
}
