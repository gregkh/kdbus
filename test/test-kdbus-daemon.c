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


int main(int argc, char *argv[])
{
	struct {
		struct kdbus_cmd_bus_make head;
		uint64_t c_size;
		uint64_t c_type;
		uint64_t cgroup_id;
		uint64_t n_size;
		uint64_t n_type;
		char name[64];
	} bus_make;
	int fd_owner;
	char *bus;
	struct conn *conn;
	struct pollfd fds[2];
	int count;
	int ret;

	printf("Starting Test Bus Daemon (press ENTER to exit)\n");

	fd_owner = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
	if (fd_owner < 0) {
		fprintf(stderr, "/dev/kdbus/control: %m\n");
		return EXIT_FAILURE;
	}

	memset(&bus_make, 0, sizeof(bus_make));
	bus_make.head.bloom_size = 8;

	bus_make.cgroup_id = cgroup_systemd();
	bus_make.c_type = KDBUS_MAKE_CGROUP;
	bus_make.c_size = KDBUS_ITEM_HEADER_SIZE + sizeof(uint64_t);

	snprintf(bus_make.name, sizeof(bus_make.name), "%u-testbus", getuid());
	bus_make.n_type = KDBUS_MAKE_NAME;
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;

	bus_make.head.size = sizeof(struct kdbus_cmd_bus_make) +
			     bus_make.c_size +
			     bus_make.n_size;
	ret = ioctl(fd_owner, KDBUS_CMD_BUS_MAKE, &bus_make);
	if (ret) {
		fprintf(stderr, "KDBUS_CMD_BUS_MAKE: %m\n");
		return EXIT_FAILURE;
	}
	printf("  Created bus '%s'\n", bus_make.name);

	if (asprintf(&bus, "/dev/kdbus/%s/bus", bus_make.name) < 0)
		return EXIT_FAILURE;

	conn = connect_to_bus(bus);
	if (!conn)
		return EXIT_FAILURE;
	printf("  Created connection %llu on bus '%s'\n", (unsigned long long)conn->id, bus_make.name);

	upload_policy(conn->fd);
	name_acquire(conn, "org.freedesktop.kdbus", 0);
	//name_acquire(conn, "foo.bar.baz", 0);
	printf("  Aquired name: org.freedesktop.kdbus\n");

	fds[0].fd = conn->fd;
	fds[1].fd = STDIN_FILENO;

	printf("  Monitoring connections:\n");

	for (count = 0;; count++) {
		int i, nfds = sizeof(fds) / sizeof(fds[0]);

		for (i = 0; i < nfds; i++) {
			fds[i].events = POLLIN | POLLPRI | POLLHUP;
			fds[i].revents = 0;
		}

		ret = poll(fds, nfds, -1);
		if (ret <= 0)
			break;

		if (fds[0].revents & POLLIN)
			msg_recv(conn);

		/* stdin */
		if (fds[1].revents & POLLIN)
			break;
	}

	printf("  Closing bus connection\n");
	close(conn->fd);
	free(conn);

	printf("  Closing bus\n");
	close(fd_owner);
	free(bus);

	return EXIT_SUCCESS;
}
