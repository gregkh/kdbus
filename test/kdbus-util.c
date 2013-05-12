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
#include <sys/mman.h>

//#include "include/uapi/kdbus/kdbus.h"
#include "../kdbus.h"

#include "kdbus-util.h"
#include "kdbus-enum.h"

struct conn *connect_to_bus(const char *path)
{
	int fd, ret;
	void *buf;
	struct {
		struct kdbus_cmd_hello hello;
		uint64_t v_size;
		uint64_t v_type;
		struct kdbus_vec vec;
	} h;
	struct conn *conn;

	memset(&h, 0, sizeof(h));

	printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "--- error %d (%m)\n", fd);
		return NULL;
	}

	buf = mmap(NULL, 128 * 1024 * 1024, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "--- error mmap (%m)\n");
		return NULL;
	}
	h.v_type = KDBUS_HELLO_POOL;
	h.v_size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	h.vec.address = (uint64_t)buf;
	h.vec.size = 128 * 1024 * 1024;

	h.hello.conn_flags = KDBUS_HELLO_ACCEPT_FD |
			     KDBUS_HELLO_ATTACH_COMM |
			     KDBUS_HELLO_ATTACH_EXE |
			     KDBUS_HELLO_ATTACH_CMDLINE |
			     KDBUS_HELLO_ATTACH_CAPS |
			     KDBUS_HELLO_ATTACH_CGROUP |
			     KDBUS_HELLO_ATTACH_SECLABEL |
			     KDBUS_HELLO_ATTACH_AUDIT;

	h.hello.size = sizeof(struct kdbus_cmd_hello) +
		       KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);

	ret = ioctl(fd, KDBUS_CMD_HELLO, &h.hello);
	if (ret) {
		fprintf(stderr, "--- error when saying hello: %d (%m)\n", ret);
		return NULL;
	}
	printf("-- Our peer ID for %s: %llu\n", path, (unsigned long long)h.hello.id);

	conn = malloc(sizeof(*conn));
	if (!conn) {
		fprintf(stderr, "unable to malloc()!?\n");
		return NULL;
	}

	conn->fd = fd;
	conn->id = h.hello.id;
	return conn;
}

int msg_send(const struct conn *conn,
		    const char *name,
		    uint64_t cookie,
		    uint64_t dst_id)
{
	struct kdbus_msg *msg;
	const char ref1[1024 * 1024] = "0123456789_0";
	const char ref2[] = "0123456789_1";
	struct kdbus_item *item;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	size += KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);

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
		item = KDBUS_ITEM_NEXT(item);
	}

	item->type = KDBUS_MSG_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uint64_t)&ref1;
	item->vec.size = sizeof(ref1);
	item = KDBUS_ITEM_NEXT(item);

	item->type = KDBUS_MSG_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uint64_t)&ref2;
	item->vec.size = sizeof(ref2);
	item = KDBUS_ITEM_NEXT(item);

	if (dst_id == KDBUS_DST_ID_BROADCAST) {
		item->type = KDBUS_MSG_BLOOM;
		item->size = KDBUS_ITEM_HEADER_SIZE + 64;
		item = KDBUS_ITEM_NEXT(item);
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
	struct kdbus_item *item = msg->items;
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
		case KDBUS_MSG_PAYLOAD_VEC:
			printf("  +%s (%llu bytes) addr=%p size=%llu '%s'\n",
			       enum_MSG(item->type), item->size, KDBUS_VEC_PTR(&item->vec),
			       (unsigned long long)item->vec.size, (char *)KDBUS_VEC_PTR(&item->vec));
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
		case KDBUS_MSG_SRC_CGROUP:
		case KDBUS_MSG_SRC_SECLABEL:
		case KDBUS_MSG_DST_NAME:
			printf("  +%s (%llu bytes) '%s' (%zu)\n",
			       enum_MSG(item->type), item->size, item->str, strlen(item->str));
			break;

		case KDBUS_MSG_SRC_CMDLINE:
		case KDBUS_MSG_SRC_NAMES: {
			size_t size = item->size - KDBUS_ITEM_HEADER_SIZE;
			char *str = item->str;
			int count = 0;

			printf("  +%s (%llu bytes) ", enum_MSG(item->type), item->size);
			while (size) {
				printf("'%s' ", str);
				size -= strlen(str) + 1;
				str += strlen(str) + 1;
				count++;
			}

			printf("(%d string%s)\n", count, (count == 1) ? "" : "s");
			break;
		}

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
	struct kdbus_msg *msg;
	int ret;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &msg);
	if (ret < 0) {
		fprintf(stderr, "error receiving message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	msg_dump(msg);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RELEASE, msg);
	if (ret < 0) {
		fprintf(stderr, "error free message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

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

unsigned int cgroup_systemd(void)
{
	char line[256];
	FILE *f;
	unsigned int id = 0;

	f = fopen("/proc/self/cgroup", "re");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		unsigned int i;

		if (strstr(line, ":name=systemd:") == NULL)
			continue;

		if (sscanf(line, "%u:", &i) != 1)
			continue;

		id = i;
		break;
	}
	fclose(f);

	return id;
}

void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size)
{
	struct kdbus_policy *dst = (struct kdbus_policy *) ((char *) cmd_policy + cmd_policy->size);

	if (cmd_policy->size + policy->size > max_size)
		return;

	memcpy(dst, policy, policy->size);
	cmd_policy->size += policy->size;
}

struct kdbus_policy *make_policy_name(const char *name)
{
	struct kdbus_policy *p;
	__u64 size;

	size = offsetof(struct kdbus_policy, name) + strlen(name) + 1;
	p = malloc(size);
	if (!p)
		return NULL;

	memset(p, 0, size);
	p->size = size;
	p->type = KDBUS_POLICY_NAME;
	strcpy(p->name, name);

	return p;
}

struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id)
{
	struct kdbus_policy *p;
	__u64 size = sizeof(*p);

	p = malloc(size);
	if (!p)
		return NULL;

	memset(p, 0, size);
	p->size = size;
	p->type = KDBUS_POLICY_ACCESS;
	p->access.type = type;
	p->access.bits = bits;
	p->access.id = id;

	return p;
}


int upload_policy(int fd)
{
	struct kdbus_cmd_policy *cmd_policy;
	struct kdbus_policy *policy;
	int ret;
	int size = 0xffff;

	cmd_policy = (struct kdbus_cmd_policy *) alloca(size);

	policy = (struct kdbus_policy *) cmd_policy->data;
	cmd_policy->size = offsetof(struct kdbus_cmd_policy, data);

	policy = make_policy_name("foo.bar.baz");
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_USER, KDBUS_POLICY_OWN, getuid());
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_RECV, 0);
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_SEND, 0);
	append_policy(cmd_policy, policy, size);

	ret = ioctl(fd, KDBUS_CMD_EP_POLICY_SET, cmd_policy);
	if (ret < 0)
		fprintf(stderr, "--- error setting EP policy: %d (%m)\n", ret);

	return ret;
}


