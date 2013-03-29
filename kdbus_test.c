#define _GNU_SOURCE
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
#include "kdbus.h"

int main(int argc, char *argv[])
{
	int fdc;
	int fdb;
	struct kdbus_cmd_name name;
	char *busname;
	char *bus;
	char *ep;
	char *ns;
	uid_t uid;
	int err;

	uid = getuid();
	if (argv[1])
		busname = argv[1];
	else if (uid > 0)
		busname = "system";
	else
		busname = "user";
	strcpy(name.name, busname);

	printf("-- opening /dev/kdbus/control\n");
	fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
	if (fdc < 0)
		return EXIT_FAILURE;

	asprintf(&ns, "mydebiancontainer");
	strcpy(name.name, ns);
	printf("-- creating namespace called %s\n", ns);
	err = ioctl(fdc, KDBUS_CMD_NS_CREATE, &name);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));

	printf("-- creating bus '%s'\n", name.name);
	err = ioctl(fdc, KDBUS_CMD_BUS_CREATE, &name);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));

	if (uid > 0)
		asprintf(&bus, "/dev/kdbus/%u-%s/bus", uid, busname);
	else
		asprintf(&bus, "/dev/kdbus/%s/bus", busname);
	printf("-- opening bus connection %s\n", bus);
	fdb = open(bus, O_RDWR|O_CLOEXEC);


	asprintf(&ep, "ep-42");
	strcpy(name.name, ep);
	printf("-- creating endpoint for bus %s called %s\n", bus, ep);
	err = ioctl(fdb, KDBUS_CMD_EP_CREATE, &name);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));

	printf("-- sleeping 10s\n");
	sleep(10);

	printf("-- closing bus connection\n");
	close(fdb);

	printf("-- closing bus master\n");
	close(fdc);
	return EXIT_SUCCESS;
}
