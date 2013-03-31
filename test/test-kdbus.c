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

struct conn {
	int fd;
	uint64_t id;
};

static struct conn *connect_to_bus(const char *path)
{
	int fd, err;
	struct kdbus_cmd_hello hello;
	struct conn *conn;

	printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "--- error %d (\"%s\")\n", fd, strerror(errno));
		return NULL;
	}

	memset(&hello, 0, sizeof(hello));
	err = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	if (err) {
		fprintf(stderr, "--- error when saying hello: %d (\"%s\")\n", err, strerror(errno));
		return NULL;
	}
	printf("-- Our peer ID for %s: %lu\n", path, (uint64_t)hello.id);

	conn = malloc(sizeof(*conn));
	if (!conn) {
		fprintf(stderr, "unable to malloc()!?\n");
		return NULL;
	}

	conn->fd = fd;
	conn->id = hello.id;
	return conn;
}

static int send_msg(const struct conn *conn,
		    const char *name,
		    uint64_t cookie,
		    uint64_t dst_id)
{
	struct kdbus_msg *msg;
	uint64_t size, extra_size = 0;
	void *extra = NULL;
	int err;

	if (name) {
		struct kdbus_msg_data *name_data;

		extra_size = sizeof(*name_data) + strlen(name) + 1;

		name_data = malloc(extra_size);
		if (!name_data) {
			fprintf(stderr, "unable to malloc()!?\n");
			return EXIT_FAILURE;
		}

		memset(name_data, 0, extra_size);

		name_data->size = extra_size;
		name_data->type = KDBUS_MSG_DST_NAMES;

		memcpy(name_data->data, name, strlen(name));
		extra = name_data;
	}

	size = sizeof(*msg) + extra_size;
	msg = malloc(size);
	if (!msg) {
		fprintf(stderr, "unable to malloc()!?\n");
		return EXIT_FAILURE;
	}

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = dst_id;
	msg->cookie = cookie;
	msg->payload_type = 0xdeadbeef;

	if (extra)
		memcpy(msg->data, extra, extra_size);

	err = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (err) {
		fprintf(stderr, "error sending message: %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}

	if (extra)
		free(extra);

	free(msg);

	return 0;
}

int main(int argc, char *argv[])
{
	struct kdbus_cmd_fname name;
	int fdc, err;
	char *busname, *bus;
	struct conn *conn_a, *conn_b;
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

	conn_a = connect_to_bus(bus);
	conn_b = connect_to_bus(bus);
	if (!conn_a || !conn_b)
		return EXIT_FAILURE;

	send_msg(conn_a, NULL, 0xc00c0001, conn_b->id);

	printf("-- sleeping 10s\n");
	sleep(10);

	printf("-- closing bus connections\n");
	close(conn_a->fd);
	close(conn_b->fd);

	printf("-- closing bus master\n");
	close(fdc);

	return EXIT_SUCCESS;
}
