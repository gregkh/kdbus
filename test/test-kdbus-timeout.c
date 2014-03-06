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

static uint64_t expected = 0;

int timeout_msg_recv(struct conn *conn)
{
	struct kdbus_cmd_recv recv = {};
	struct kdbus_msg *msg;
	int ret;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	if (ret < 0) {
		fprintf(stderr, "error receiving message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.offset);
	expected &= ~(1ULL << msg->cookie_reply);
	printf("Got message timeout for cookie %llu\n", msg->cookie_reply);

	ret = ioctl(conn->fd, KDBUS_CMD_FREE, &recv.offset);
	if (ret < 0) {
		fprintf(stderr, "error free message: %d (%m)\n", ret);
		return EXIT_FAILURE;
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
	struct pollfd fd;
	int fdc, ret, i, n_msgs = 4;

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

	fd.fd = conn_b->fd;

	/* send messages that expect a reply (within 1 sec), but never answer it */
	for (i = 0; i < n_msgs; i++) {
		printf("Sending message with cookie %u ...\n", i);
		msg_send(conn_b, NULL, i, KDBUS_MSG_FLAGS_EXPECT_REPLY, (i + 1) * 1000ULL * 1000ULL * 1000ULL, 0, conn_a->id);
		expected |= 1ULL << i;
	}

	for (;;) {
		fd.events = POLLIN | POLLPRI | POLLHUP;
		fd.revents = 0;

		ret = poll(&fd, 1, (n_msgs + 1) * 1000);
		if (ret == 0)
			printf("--- timeout\n");
		if (ret <= 0)
			break;

		if (fd.revents & POLLIN)
			timeout_msg_recv(conn_b);

		if (expected == 0)
			break;
	}

	if (expected != 0) {
		for (i = 0; i < 64; i++)
			if (expected & (1ULL << i))
				printf("No timeout notification received for cookie %u\n", i);
	} else {
		printf("Timeout notifications received for all messages. Good.\n");
	}

	close(conn_a->fd);
	close(conn_b->fd);
	free(conn_a);
	free(conn_b);
	close(fdc);
	free(bus);

	return expected ? EXIT_FAILURE : EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		while (run_test() == 0);

	return run_test();
}
