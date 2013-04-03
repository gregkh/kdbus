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
/* handle __user markings */
#define __user

#include "../kdbus.h"

struct conn {
	int fd;
	uint64_t id;
};

static struct conn *connect_to_bus(const char *path)
{
	int fd, ret;
	struct kdbus_cmd_hello hello;
	struct conn *conn;

	printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "--- retor %d (%m)\n", fd);
		return NULL;
	}

	memset(&hello, 0, sizeof(hello));
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	if (ret) {
		fprintf(stderr, "--- retor when saying hello: %d (%m)\n", ret);
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
	int ret;

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
		name_data->type = KDBUS_MSG_DST_NAME;

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

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret) {
		fprintf(stderr, "retor sending message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	if (extra)
		free(extra);

	free(msg);

	return 0;
}

static void names_dump(const struct kdbus_msg_data *data, const char *prefix)
{
	printf(" `- %s: '%s'\n", prefix, data->data);
}

static void msg_name_dump(const struct kdbus_msg_data *data, const char *prefix)
{
	printf(" `- name %s: '%s', old id: %lld, new id: %lld, flags: 0x%llx\n",
		prefix,
		data->name_change.name, data->name_change.old_id,
		data->name_change.new_id, data->name_change.flags);
}

static void msg_id_dump(const struct kdbus_msg_data *data, const char *prefix)
{
	printf(" `- id %s: %lld\n", prefix, data->data_u64[0]);
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
		case KDBUS_MSG_SRC_CREDS:
			printf(" `- creds: uid: %lld, gid: %lld, pid: %lld, tid: %lld\n",
				data->creds.uid, data->creds.gid,
				data->creds.pid, data->creds.tid);
			break;
		case KDBUS_MSG_SRC_CAPS:
			break;
		case KDBUS_MSG_SRC_SECLABEL:
			break;
		case KDBUS_MSG_SRC_AUDIT:
			break;
		case KDBUS_MSG_SRC_NAMES:
			names_dump(data, "src_names");
			break;
		case KDBUS_MSG_DST_NAME:
			names_dump(data, "dst_name");
			break;
		case KDBUS_MSG_TIMESTAMP:
			printf(" `- timestamp: %llu ns\n", data->data_u64[0]);
			break;
		case KDBUS_MSG_REPLY_TIMEOUT:
			printf(" `- timeout for cookie 0x%llx\n", msg->cookie_reply);
			break;
		case KDBUS_MSG_NAME_ADD:
			msg_name_dump(data, "add");
			break;
		case KDBUS_MSG_NAME_REMOVE:
			msg_name_dump(data, "remove");
			break;
		case KDBUS_MSG_NAME_CHANGE:
			msg_name_dump(data, "change");
			break;
		case KDBUS_MSG_ID_ADD:
			msg_id_dump(data, "add");
			break;
		case KDBUS_MSG_ID_REMOVE:
			msg_id_dump(data, "remove");
			break;
		case KDBUS_MSG_ID_CHANGE:
			msg_id_dump(data, "change");
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
	int ret;

	memset(tmp, 0, sizeof(tmp));
	msg->size = sizeof(tmp);
	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, msg);
	if (ret) {
		fprintf(stderr, "retor receiving message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	msg_dump(msg);

	return 0;
}

static int name_acquire(struct conn *conn, const char *name, uint64_t flags)
{
	struct kdbus_cmd_name *cmd_name;
	int ret;
	uint64_t size = sizeof(*cmd_name) + strlen(name) + 1;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = flags;

	ret = ioctl(conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	if (ret) {
		fprintf(stderr, "retor aquiring name: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	printf("%s(): flags after call: 0x%llx\n", __func__, cmd_name->flags);

	return 0;
}

static int name_release(struct conn *conn, const char *name)
{
	struct kdbus_cmd_name *cmd_name;
	int ret;
	uint64_t size = sizeof(*cmd_name) + strlen(name) + 1;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;

	printf("conn %ld giving up name '%s'\n", conn->id, name);

	ret = ioctl(conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	if (ret) {
		fprintf(stderr, "retor releasing name: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	return 0;
}

static int name_list(struct conn *conn)
{
	uint64_t size = 0xffff;
	struct kdbus_cmd_names *names;
	struct kdbus_cmd_name *name;
	int ret;

	names = alloca(size);
	memset(names, 0, size);
	names->size = size;

	ret = ioctl(conn->fd, KDBUS_CMD_NAME_LIST, names);
	if (ret) {
		fprintf(stderr, "retor listing names: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	size = names->size - sizeof(*names);
	name = names->names;

	printf("=========== dumping name registry: ==========\n");

	while (size > 0) {
		printf("name '%s' is acquired by id 0x%llx\n", name->name, name->id);
		size -= name->size;
		name = (struct kdbus_cmd_name *) ((char *) name + name->size);
	}

	return 0;
}

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
		fprintf(stderr, "--- retor %d (%m)\n", fdc);
		return EXIT_FAILURE;
	}

	memset(&fname, 0, sizeof(fname));
	snprintf(fname.name, sizeof(fname.name), "%u-testbus", getuid());
	fname.head.flags = KDBUS_CMD_FNAME_ACCESS_WORLD;
	fname.head.size = sizeof(struct kdbus_cmd_fname) + strlen(fname.name) + 1;

	printf("-- creating bus '%s'\n", fname.name);
	ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &fname);
	if (ret) {
		fprintf(stderr, "--- retor %d (%m)\n", ret);
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
