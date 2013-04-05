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
		struct kdbus_cmd_fname head;
		char name[64];
	} fname;
	int fdc, ret, cookie;
	char *bus;
	struct conn *conn_a, *conn_b;
	struct pollfd fds[2];
	int count;

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

	name_acquire(conn_a, "foo.bar.baz", 0);
	name_acquire(conn_b, "foo.bar.baz", KDBUS_CMD_NAME_QUEUE);
	name_list(conn_b);

	cookie = 0;
	msg_send(conn_b, "foo.bar.baz", 0xc0000000 | cookie, ~0ULL);

	fds[0].fd = conn_a->fd;
	fds[1].fd = conn_b->fd;

	printf("-- entering poll loop ...\n");

	for (count = 0;; count++) {
		int i, nfds = sizeof(fds) / sizeof(fds[0]);

		for (i = 0; i < nfds; i++) {
			fds[i].events = POLLIN | POLLPRI | POLLHUP;
			fds[i].revents = 0;
		}

		ret = poll(fds, nfds, 3000);
		if (ret <= 0)
			break;

		if (fds[0].revents & POLLIN) {
			if (count > 2)
				name_release(conn_a, "foo.bar.baz");

			msg_recv(conn_a);
			msg_send(conn_a, NULL, 0xc0000000 | cookie++, conn_b->id);
		}
		if (fds[1].revents & POLLIN) {
			msg_recv(conn_b);
			msg_send(conn_b, NULL, 0xc0000000 | cookie++, conn_a->id);
		}

		name_list(conn_b);

		if (count > 10)
			break;
	}

	printf("-- closing bus connections\n");
	close(conn_a->fd);
	close(conn_b->fd);
	free(conn_a);
	free(conn_b);

	printf("-- closing bus master\n");
	close(fdc);
	free(bus);

	return EXIT_SUCCESS;
}
