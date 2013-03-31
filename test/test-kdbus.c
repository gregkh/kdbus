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
	printf("-- Our peer ID for %s: %llu\n", path, (unsigned long long)hello.id);

	conn = malloc(sizeof(*conn));
	if (!conn) {
		fprintf(stderr, "unable to malloc()!?\n");
		return NULL;
	}

	conn->fd = fd;
	conn->id = hello.id;
	return conn;
}

static int msg_send(const struct conn *conn,
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
	msg->dst_id = name ? 0 : dst_id;
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

static void msg_dump(struct kdbus_msg *msg)
{
	uint64_t size = msg->size - offsetof(struct kdbus_msg, data);
	const struct kdbus_msg_data *data = msg->data;

	printf("msg size=%llu, flags=0x%llx, dst_id=%llu, src_id=%llu, "
		"cookie=0x%llx payload_type=0x%llx, timeout=%llu\n",
		(unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		(unsigned long long) msg->dst_id,
		(unsigned long long) msg->src_id,
		(unsigned long long) msg->cookie,
		(unsigned long long) msg->payload_type,
		(unsigned long long) msg->timeout);

	while (size > 0 && size >= data->size) {
		printf("`- msg_data size=%llu, type=0x%llx\n",
			data->size, data->type);

		switch (data->type) {
		case KDBUS_MSG_TIMESTAMP:
			printf(" `- timestamp: %llu ns\n", data->data_u64[0]);
			break;
		}

		size -= data->size;
		data = (struct kdbus_msg_data *) (((char *) data) + data->size);
	}
}

static int msg_recv(struct conn *conn)
{
	char tmp[0xffff];
	struct kdbus_msg *msg = (struct kdbus_msg *) tmp;
	int err;

	msg->size = sizeof(tmp);
	err = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, msg);
	if (err) {
		fprintf(stderr, "error receiving message: %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}

	msg_dump(msg);

	return 0;
}

static int name_acquire(struct conn *conn, const char *name)
{
	struct kdbus_cmd_name *cmd_name;
	int err;
	uint64_t size = sizeof(*cmd_name) + strlen(name) + 1;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;

	err = ioctl(conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	if (err) {
		fprintf(stderr, "error aquiring name: %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}

	printf("%s(): flags after call: 0x%llx\n", __func__, cmd_name->flags);

	return 0;
}

static int name_release(struct conn *conn, const char *name)
{
	struct kdbus_cmd_name *cmd_name;
	int err;
	uint64_t size = sizeof(*cmd_name) + strlen(name) + 1;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;

	err = ioctl(conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	if (err) {
		fprintf(stderr, "error releasing name: %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}

	return 0;
}

static int name_list(struct conn *conn)
{
	uint64_t size = 0xffff;
	struct kdbus_cmd_names *names;
	struct kdbus_cmd_name *name;
	int err;

	names = alloca(size);
	names->size = size;

	err = ioctl(conn->fd, KDBUS_CMD_NAME_LIST, names);
	if (err) {
		fprintf(stderr, "error listing names: %d (\"%s\")\n", err, strerror(errno));
		return EXIT_FAILURE;
	}

	size = names->size - sizeof(*names);
	name = names->names;

	while (size > 0) {
		printf("name '%s' is acquired by id 0x%llx\n", name->name, name->id);
		size -= name->size;
		name = (struct kdbus_cmd_name *) ((char *) name + name->size);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct kdbus_cmd_fname name;
	int fdc, err, cookie;
	char *busname, *bus;
	struct conn *conn_a, *conn_b;
	struct pollfd fds[2];
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

	name_acquire(conn_b, "foo.bar.blubb");
	//name_release(conn_b, "foo.bar.blubb");

	name_list(conn_b);

	cookie = 0;
	msg_send(conn_a, "foo.bar.blubb", 0xc0000000 | cookie, ~0ULL);

	fds[0].fd = conn_a->fd;
	fds[1].fd = conn_b->fd;


	printf("-- entering poll loop ...\n");

	while (1) {
		int i, nfds = sizeof(fds) / sizeof(fds[0]);

		for (i = 0; i < nfds; i++) {
			fds[i].events = POLLIN | POLLPRI | POLLHUP;
			fds[i].revents = 0;
		}

		err = poll(fds, nfds, -1);
		if (err < 0)
			break;

		if (fds[0].revents & POLLIN) {
			msg_recv(conn_a);
//			msg_send(conn_a, NULL, 0xc0000000 | cookie++, conn_b->id);
		}
		if (fds[1].revents & POLLIN) {
			msg_recv(conn_b);
//			msg_send(conn_b, NULL, 0xc0000000 | cookie++, conn_a->id);
		}
	}

	printf("-- closing bus connections\n");
	close(conn_a->fd);
	close(conn_b->fd);

	printf("-- closing bus master\n");
	close(fdc);

	return EXIT_SUCCESS;
}
