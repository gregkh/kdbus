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

int main(int argc, char *argv[])
{
	int fdc;
	int fdb;
	struct kdbus_cmd_name name;
	char *busname;
	char *bus;
	uid_t uid;
	int err;

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
	printf("-- opening bus connection %s\n", bus);
	fdb = open(bus, O_RDWR|O_CLOEXEC);
	if (fdb < 0) {
		fprintf(stderr, "--- error %d (\"%s\")\n", fdb, strerror(errno));
		return EXIT_FAILURE;
	}

	printf("-- sleeping 10s\n");
	sleep(10);

	printf("-- closing bus connection\n");
	close(fdb);

	printf("-- closing bus master\n");
	close(fdc);

	return EXIT_SUCCESS;
}
