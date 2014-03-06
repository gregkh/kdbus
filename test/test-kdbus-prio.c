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

static int msg_recv_prio(struct conn *conn, int64_t priority)
{
	struct kdbus_cmd_recv recv = {
		.flags = KDBUS_RECV_USE_PRIORITY,
		.priority = priority,
	};
	struct kdbus_msg *msg;
	int ret;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error receiving message: %d (%m)\n", ret);
		return ret;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.offset);
	msg_dump(conn, msg);

	ret = ioctl(conn->fd, KDBUS_CMD_FREE, &recv.offset);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error free message: %d (%m)\n", ret);
		return ret;
	}

	return 0;
}

static int run_test(void)
{
	struct {
		struct kdbus_cmd_make head;

		/* bloom size item */
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_bloom_parameter bloom;
		} bs;

		/* name item */
		uint64_t n_size;
		uint64_t n_type;
		char name[64];
	} bus_make;
	char *bus;
	struct conn *conn_a, *conn_b;
	uint64_t cookie;
	int fdc;
	int ret;

	printf("-- opening /dev/" KBUILD_MODNAME "/control\n");
	fdc = open("/dev/" KBUILD_MODNAME "/control", O_RDWR|O_CLOEXEC);
	if (fdc < 0) {
		fprintf(stderr, "--- error %d (%m)\n", fdc);
		return EXIT_FAILURE;
	}

	memset(&bus_make, 0, sizeof(bus_make));
	bus_make.bs.size = sizeof(bus_make.bs);
	bus_make.bs.type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bs.bloom.size = 64;
	bus_make.bs.bloom.n_hash = 1;

	snprintf(bus_make.name, sizeof(bus_make.name), "%u-testbus", getuid());
	bus_make.n_type = KDBUS_ITEM_MAKE_NAME;
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;

	bus_make.head.size = sizeof(struct kdbus_cmd_make) +
			     sizeof(bus_make.bs) +
			     bus_make.n_size;

	printf("-- creating bus '%s'\n", bus_make.name);
	ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &bus_make);
	if (ret) {
		fprintf(stderr, "--- error %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	if (asprintf(&bus, "/dev/" KBUILD_MODNAME "/%s/bus", bus_make.name) < 0)
		return EXIT_FAILURE;

	conn_a = kdbus_hello(bus, 0);
	conn_b = kdbus_hello(bus, 0);
	if (!conn_a || !conn_b)
		return EXIT_FAILURE;

	cookie = 0;
	msg_send(conn_b, NULL, ++cookie, 0, 0,   25, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0, -600, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0,   10, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0,  -35, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0, -100, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0,   20, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0,  -15, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0, -800, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0, -150, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0, -150, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0,   10, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0, -800, conn_a->id);
	msg_send(conn_b, NULL, ++cookie, 0, 0,  -10, conn_a->id);

	printf("--- get priority -200\n");
	for (;;) {
		if (msg_recv_prio(conn_a, -200) < 0)
			break;
	}

	printf("--- get priority -100\n");
	for (;;) {
		if (msg_recv_prio(conn_a, -100) < 0)
			break;
	}

	printf("--- get priority 10\n");
	for (;;) {
		if (msg_recv_prio(conn_a, 10) < 0)
			break;
	}

	printf("--- get priority (all)\n");
	for (;;) {
		if (msg_recv(conn_a) < 0)
			break;
	}

	close(conn_a->fd);
	close(conn_b->fd);
	free(conn_a);
	free(conn_b);
	close(fdc);
	free(bus);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		while (run_test() == 0);

	return run_test();
}
