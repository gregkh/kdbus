/*
 * Copyright (C) 2013 Daniel Mack
 * Copyright (C) 2013 Kay Sievers
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <stdio.h>
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

	hello.conn_flags = KDBUS_CMD_HELLO_ACCEPT_FD |
			   KDBUS_CMD_HELLO_ACCEPT_MMAP |
			   KDBUS_CMD_HELLO_ATTACH_COMM |
			   KDBUS_CMD_HELLO_ATTACH_EXE |
			   KDBUS_CMD_HELLO_ATTACH_CMDLINE |
			   KDBUS_CMD_HELLO_ATTACH_CAPS |
			   KDBUS_CMD_HELLO_ATTACH_CGROUP |
			   KDBUS_CMD_HELLO_ATTACH_SECLABEL |
			   KDBUS_CMD_HELLO_ATTACH_AUDIT;

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
	const char ref[0x2000] = "REFERENCED";
	struct kdbus_msg_item *item;
	uint64_t size;
	int ret;

	size = sizeof(*msg);
	size += KDBUS_ITEM_HEADER_SIZE + 16;
	size += KDBUS_ITEM_HEADER_SIZE + sizeof("INLINE1");
	
	if (dst_id == KDBUS_DST_ID_BROADCAST)
		size += KDBUS_ITEM_HEADER_SIZE + 64;
	
	if (name)
		size += KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;

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

	item = msg->items;

	if (name) {
		item->type = KDBUS_MSG_DST_NAME;
		item->size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
		strcpy(item->str, name);
		item = (struct kdbus_msg_item *) ((char *)(item) + KDBUS_ALIGN8(item->size));
	}

	item->type = KDBUS_MSG_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + 16;
	item->vec.address = (uint64_t)&ref;
	item->vec.size = sizeof(ref);
	item = (struct kdbus_msg_item *) ((char *)(item) + KDBUS_ALIGN8(item->size));

	item->type = KDBUS_MSG_PAYLOAD;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof("INLINE1");
	memcpy(item->data, "INLINE1", sizeof("INLINE1"));
	item = (struct kdbus_msg_item *) ((char *)(item) + KDBUS_ALIGN8(item->size));

	if (dst_id == KDBUS_DST_ID_BROADCAST) {
		item->type = KDBUS_MSG_BLOOM;
		item->size = KDBUS_ITEM_HEADER_SIZE + 64;
		item = (struct kdbus_msg_item *) ((char *)(item) + KDBUS_ALIGN8(item->size));
	}

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	if (ret) {
		fprintf(stderr, "error sending message: %d err %d (%m)\n", ret, errno);
		return EXIT_FAILURE;
	}

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
	struct kdbus_msg_item *item = msg->items;
	char buf[32];

	printf("MESSAGE: %s (%llu bytes) flags=0x%llx, %s → %s, cookie=%llu, timeout=%llu\n",
		enum_PAYLOAD(msg->payload_type), (unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		msg_id(msg->src_id, buf), msg_id(msg->dst_id, buf),
		(unsigned long long) msg->cookie, (unsigned long long) msg->timeout_ns);

	KDBUS_ITEM_FOREACH(item, msg) {
		if (item->size <= KDBUS_ITEM_HEADER_SIZE) {
			printf("  +%s (%llu bytes) invalid data record\n", enum_MSG(item->type), item->size);
			break;
		}

		switch (item->type) {
		case KDBUS_MSG_PAYLOAD:
			printf("  +%s (%llu bytes) '%s'\n",
			       enum_MSG(item->type), item->size, item->data);
			break;

		case KDBUS_MSG_SRC_CREDS:
			printf("  +%s (%llu bytes) uid=%lld, gid=%lld, pid=%lld, tid=%lld, starttime=%lld\n",
				enum_MSG(item->type), item->size,
				item->creds.uid, item->creds.gid,
				item->creds.pid, item->creds.tid,
				item->creds.starttime);
			break;

		case KDBUS_MSG_SRC_PID_COMM:
		case KDBUS_MSG_SRC_TID_COMM:
		case KDBUS_MSG_SRC_EXE:
		case KDBUS_MSG_SRC_CMDLINE:
		case KDBUS_MSG_SRC_CGROUP:
		case KDBUS_MSG_SRC_SECLABEL:
		case KDBUS_MSG_SRC_NAMES:
		case KDBUS_MSG_DST_NAME:
			printf("  +%s (%llu bytes) '%s' (%zu)\n",
			       enum_MSG(item->type), item->size, item->str, strlen(item->str));
			break;

		case KDBUS_MSG_SRC_AUDIT:
			printf("  +%s (%llu bytes) loginuid=%llu sessionid=%llu\n",
			       enum_MSG(item->type), item->size,
			       (unsigned long long)item->data64[0],
			       (unsigned long long)item->data64[1]);
			break;

		case KDBUS_MSG_SRC_CAPS: {
			int n;
			uint32_t *cap;
			int i;

			printf("  +%s (%llu bytes) len=%llu bytes)\n",
			       enum_MSG(item->type), item->size,
			       (unsigned long long)item->size - KDBUS_ITEM_HEADER_SIZE);

			cap = item->data32;
			n = (item->size - KDBUS_ITEM_HEADER_SIZE) / 4 / sizeof(uint32_t);

			printf("    CapInh=");
			for (i = 0; i < n; i++)
				printf("%08x", cap[(0 * n) + (n - i - 1)]);

			printf(" CapPrm=");
			for (i = 0; i < n; i++)
				printf("%08x", cap[(1 * n) + (n - i - 1)]);

			printf(" CapEff=");
			for (i = 0; i < n; i++)
				printf("%08x", cap[(2 * n) + (n - i - 1)]);

			printf(" CapInh=");
			for (i = 0; i < n; i++)
				printf("%08x", cap[(3 * n) + (n - i - 1)]);
			printf("\n");
			break;
		}

		case KDBUS_MSG_TIMESTAMP:
			printf("  +%s (%llu bytes) realtime=%lluns monotonic=%lluns\n",
			       enum_MSG(item->type), item->size,
			       (unsigned long long)item->timestamp.realtime_ns,
			       (unsigned long long)item->timestamp.monotonic_ns);
			break;

		case KDBUS_MSG_REPLY_TIMEOUT:
			printf("  +%s (%llu bytes) cookie=%llu\n",
			       enum_MSG(item->type), item->size, msg->cookie_reply);
			break;

		case KDBUS_MSG_NAME_ADD:
		case KDBUS_MSG_NAME_REMOVE:
		case KDBUS_MSG_NAME_CHANGE:
			printf("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, flags=0x%llx\n",
				enum_MSG(item->type), (unsigned long long) item->size,
				item->name_change.name, item->name_change.old_id,
				item->name_change.new_id, item->name_change.flags);
			break;

		case KDBUS_MSG_ID_ADD:
		case KDBUS_MSG_ID_REMOVE:
			printf("  +%s (%llu bytes) id=%llu flags=%llu\n",
			       enum_MSG(item->type), (unsigned long long) item->size,
			       (unsigned long long) item->id_change.id,
			       (unsigned long long) item->id_change.flags);
			break;

		default:
			printf("  +%s (%llu bytes)\n", enum_MSG(item->type), item->size);
			break;
		}
	}

	if ((char *)item - ((char *)msg + msg->size) >= 8)
		printf("invalid padding at end of message\n");

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
	cmd_name->conn_flags = flags;

	ret = ioctl(conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	if (ret) {
		fprintf(stderr, "error aquiring name: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	printf("%s(): flags after call: 0x%llx\n", __func__, cmd_name->conn_flags);

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

	printf("conn %lld giving up name '%s'\n", (unsigned long long)conn->id, name);

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
