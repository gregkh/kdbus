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

struct conn *connect_to_bus(const char *path)
{
	int fd, ret;
	struct kdbus_cmd_hello hello;
	struct conn *conn;

	printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "--- error %d (%m)\n", fd);
		return NULL;
	}

	memset(&hello, 0, sizeof(hello));
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	if (ret) {
		fprintf(stderr, "--- error when saying hello: %d (%m)\n", ret);
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

int msg_send(const struct conn *conn,
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
	msg->payload_type = KDBUS_PAYLOAD_DBUS1;

	if (extra)
		memcpy(msg->data, extra, extra_size);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret) {
		fprintf(stderr, "error sending message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	if (extra)
		free(extra);

	free(msg);

	return 0;
}

char *msg_id(uint64_t id, char *buf)
{
	if (id == 0)
		return "KERNEL";
	if (id == ~0ULL)
		return "BROADCAST";
	sprintf(buf, "%llu", (unsigned long long)id);
	return buf;
}

void msg_dump(struct kdbus_msg *msg)
{
	uint64_t size = msg->size - offsetof(struct kdbus_msg, data);
	const struct kdbus_msg_data *data = msg->data;
	char buf[32];

	printf("MESSAGE: %s (%llu bytes) flags=0x%llx, %s → %s, cookie=%llu, timeout=%llu\n",
		enum_PAYLOAD(msg->payload_type), (unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		msg_id(msg->src_id, buf), msg_id(msg->dst_id, buf),
		(unsigned long long) msg->cookie, (unsigned long long) msg->timeout);

	while (size > 0 && size >= data->size) {
		switch (data->type) {
			printf("  +%s (%llu bytes) uid=%lld, gid=%lld, pid=%lld, tid=%lld\n",
				enum_MSG(data->type), data->size,
				data->creds.uid, data->creds.gid,
				data->creds.pid, data->creds.tid);
			break;

		case KDBUS_MSG_SRC_CAPS:
		case KDBUS_MSG_SRC_SECLABEL:
		case KDBUS_MSG_SRC_AUDIT:
		case KDBUS_MSG_SRC_NAMES:
		case KDBUS_MSG_DST_NAME:
			printf("  +%s (%llu bytes) '%s'\n",
			       enum_MSG(data->type), data->size, data->data);
			break;

		case KDBUS_MSG_TIMESTAMP:
			printf("  +%s (%llu bytes) %llu ns\n",
			       enum_MSG(data->type), data->size, (unsigned long long)data->ts_ns);
			break;

		case KDBUS_MSG_REPLY_TIMEOUT:
			printf("  +%s (%llu bytes) cookie=%llu\n",
			       enum_MSG(data->type), data->size, msg->cookie_reply);
			break;

		case KDBUS_MSG_NAME_ADD:
		case KDBUS_MSG_NAME_REMOVE:
		case KDBUS_MSG_NAME_CHANGE:
			printf("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, flags=0x%llx\n",
				enum_MSG(data->type), (unsigned long long) data->size,
				data->name_change.name, data->name_change.old_id,
				data->name_change.new_id, data->name_change.flags);
			break;

		case KDBUS_MSG_ID_ADD:
		case KDBUS_MSG_ID_REMOVE:
		case KDBUS_MSG_ID_CHANGE:
			printf("  +%s (%llu bytes) %llu\n",
			       enum_MSG(data->type), (unsigned long long) data->size,
			       (unsigned long long) data->data_u64[0]);
			break;
		}

		size -= data->size;
		data = (struct kdbus_msg_data *) (((char *) data) + data->size);
	}

	printf("\n");
}

int msg_recv(struct conn *conn)
{
	char tmp[0xffff];
	struct kdbus_msg *msg = (struct kdbus_msg *) tmp;
	int ret;

	memset(tmp, 0, sizeof(tmp));
	msg->size = sizeof(tmp);
	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, msg);
	if (ret) {
		fprintf(stderr, "error receiving message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	msg_dump(msg);

	return 0;
}

int name_acquire(struct conn *conn, const char *name, uint64_t flags)
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
		fprintf(stderr, "error aquiring name: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	printf("%s(): flags after call: 0x%llx\n", __func__, cmd_name->flags);

	return 0;
}

int name_release(struct conn *conn, const char *name)
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
		fprintf(stderr, "error releasing name: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	return 0;
}

int name_list(struct conn *conn)
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
		fprintf(stderr, "error listing names: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	size = names->size - sizeof(*names);
	name = names->names;

	printf("REGISTRY:\n");

	while (size > 0) {
		printf("  '%s' is acquired by id %llx\n", name->name, name->id);
		size -= name->size;
		name = (struct kdbus_cmd_name *) ((char *) name + name->size);
	}

	printf("\n");

	return 0;
}
