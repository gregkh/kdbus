/*
 * Copyright (C) 2013-2015 Daniel Mack
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2014-2015 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <grp.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/unistd.h>
#ifndef MFD_CLOEXEC
#include <linux/memfd.h>
#endif

#ifndef __NR_memfd_create
  #ifdef __x86_64__
    #define __NR_memfd_create 319
  #elif defined __arm__
    #define __NR_memfd_create 385
  #else
    #define __NR_memfd_create 356
  #endif
#endif

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#ifndef F_ADD_SEALS
#define F_LINUX_SPECIFIC_BASE  1024
#define F_ADD_SEALS     (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS     (F_LINUX_SPECIFIC_BASE + 10)
#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#endif

int kdbus_util_verbose = true;

int kdbus_sysfs_get_parameter_mask(const char *path, uint64_t *mask)
{
	int ret;
	FILE *file;
	unsigned long long value;

	file = fopen(path, "r");
	if (!file) {
		ret = -errno;
		kdbus_printf("--- error fopen(): %d (%m)\n", ret);
		return ret;
	}

	ret = fscanf(file, "%llu", &value);
	if (ret != 1) {
		if (ferror(file))
			ret = -errno;
		else
			ret = -EIO;

		kdbus_printf("--- error fscanf(): %d\n", ret);
		fclose(file);
		return ret;
	}

	*mask = (uint64_t)value;

	fclose(file);

	return 0;
}

int kdbus_sysfs_set_parameter_mask(const char *path, uint64_t mask)
{
	int ret;
	FILE *file;

	file = fopen(path, "w");
	if (!file) {
		ret = -errno;
		kdbus_printf("--- error open(): %d (%m)\n", ret);
		return ret;
	}

	ret = fprintf(file, "%llu", (unsigned long long)mask);
	if (ret <= 0) {
		ret = -EIO;
		kdbus_printf("--- error fprintf(): %d\n", ret);
	}

	fclose(file);

	return ret > 0 ? 0 : ret;
}

int kdbus_create_bus(int control_fd, const char *name,
		     uint64_t req_meta, uint64_t owner_meta,
		     char **path)
{
	struct {
		struct kdbus_cmd cmd;

		/* bloom size item */
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_bloom_parameter bloom;
		} bp;

		/* required and owner metadata items */
		struct {
			uint64_t size;
			uint64_t type;
			uint64_t flags;
		} attach[2];

		/* name item */
		struct {
			uint64_t size;
			uint64_t type;
			char str[64];
		} name;
	} bus_make;
	int ret;

	memset(&bus_make, 0, sizeof(bus_make));
	bus_make.bp.size = sizeof(bus_make.bp);
	bus_make.bp.type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bp.bloom.size = 64;
	bus_make.bp.bloom.n_hash = 1;

	snprintf(bus_make.name.str, sizeof(bus_make.name.str),
		 "%u-%s", getuid(), name);

	bus_make.attach[0].type = KDBUS_ITEM_ATTACH_FLAGS_RECV;
	bus_make.attach[0].size = sizeof(bus_make.attach[0]);
	bus_make.attach[0].flags = req_meta;

	bus_make.attach[1].type = KDBUS_ITEM_ATTACH_FLAGS_SEND;
	bus_make.attach[1].size = sizeof(bus_make.attach[0]);
	bus_make.attach[1].flags = owner_meta;

	bus_make.name.type = KDBUS_ITEM_MAKE_NAME;
	bus_make.name.size = KDBUS_ITEM_HEADER_SIZE +
			     strlen(bus_make.name.str) + 1;

	bus_make.cmd.flags = KDBUS_MAKE_ACCESS_WORLD;
	bus_make.cmd.size = sizeof(bus_make.cmd) +
			     bus_make.bp.size +
			     bus_make.attach[0].size +
			     bus_make.attach[1].size +
			     bus_make.name.size;

	kdbus_printf("Creating bus with name >%s< on control fd %d ...\n",
		     name, control_fd);

	ret = kdbus_cmd_bus_make(control_fd, &bus_make.cmd);
	if (ret < 0) {
		kdbus_printf("--- error when making bus: %d (%m)\n", ret);
		return ret;
	}

	if (ret == 0 && path)
		*path = strdup(bus_make.name.str);

	return ret;
}

struct kdbus_conn *
kdbus_hello(const char *path, uint64_t flags,
	    const struct kdbus_item *item, size_t item_size)
{
	struct kdbus_cmd_free cmd_free = {};
	int fd, ret;
	struct {
		struct kdbus_cmd_hello hello;

		struct {
			uint64_t size;
			uint64_t type;
			char str[16];
		} conn_name;

		uint8_t extra_items[item_size];
	} h;
	struct kdbus_conn *conn;

	memset(&h, 0, sizeof(h));

	if (item_size > 0)
		memcpy(h.extra_items, item, item_size);

	kdbus_printf("-- opening bus connection %s\n", path);
	fd = open(path, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		kdbus_printf("--- error %d (%m)\n", fd);
		return NULL;
	}

	h.hello.flags = flags | KDBUS_HELLO_ACCEPT_FD;
	h.hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	h.hello.attach_flags_recv = _KDBUS_ATTACH_ALL;
	h.conn_name.type = KDBUS_ITEM_CONN_DESCRIPTION;
	strcpy(h.conn_name.str, "this-is-my-name");
	h.conn_name.size = KDBUS_ITEM_HEADER_SIZE + strlen(h.conn_name.str) + 1;

	h.hello.size = sizeof(h);
	h.hello.pool_size = POOL_SIZE;

	ret = kdbus_cmd_hello(fd, (struct kdbus_cmd_hello *) &h.hello);
	if (ret < 0) {
		kdbus_printf("--- error when saying hello: %d (%m)\n", ret);
		return NULL;
	}
	kdbus_printf("-- Our peer ID for %s: %llu -- bus uuid: '%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x'\n",
		     path, (unsigned long long)h.hello.id,
		     h.hello.id128[0],  h.hello.id128[1],  h.hello.id128[2],
		     h.hello.id128[3],  h.hello.id128[4],  h.hello.id128[5],
		     h.hello.id128[6],  h.hello.id128[7],  h.hello.id128[8],
		     h.hello.id128[9],  h.hello.id128[10], h.hello.id128[11],
		     h.hello.id128[12], h.hello.id128[13], h.hello.id128[14],
		     h.hello.id128[15]);

	cmd_free.size = sizeof(cmd_free);
	cmd_free.offset = h.hello.offset;
	kdbus_cmd_free(fd, &cmd_free);

	conn = malloc(sizeof(*conn));
	if (!conn) {
		kdbus_printf("unable to malloc()!?\n");
		return NULL;
	}

	conn->buf = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (conn->buf == MAP_FAILED) {
		free(conn);
		close(fd);
		kdbus_printf("--- error mmap (%m)\n");
		return NULL;
	}

	conn->fd = fd;
	conn->id = h.hello.id;
	return conn;
}

struct kdbus_conn *
kdbus_hello_registrar(const char *path, const char *name,
		      const struct kdbus_policy_access *access,
		      size_t num_access, uint64_t flags)
{
	struct kdbus_item *item, *items;
	size_t i, size;

	size = KDBUS_ITEM_SIZE(strlen(name) + 1) +
		num_access * KDBUS_ITEM_SIZE(sizeof(*access));

	items = alloca(size);

	item = items;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
	item->type = KDBUS_ITEM_NAME;
	strcpy(item->str, name);
	item = KDBUS_ITEM_NEXT(item);

	for (i = 0; i < num_access; i++) {
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     sizeof(struct kdbus_policy_access);
		item->type = KDBUS_ITEM_POLICY_ACCESS;

		item->policy_access.type = access[i].type;
		item->policy_access.access = access[i].access;
		item->policy_access.id = access[i].id;

		item = KDBUS_ITEM_NEXT(item);
	}

	return kdbus_hello(path, flags, items, size);
}

struct kdbus_conn *kdbus_hello_activator(const char *path, const char *name,
				   const struct kdbus_policy_access *access,
				   size_t num_access)
{
	return kdbus_hello_registrar(path, name, access, num_access,
				     KDBUS_HELLO_ACTIVATOR);
}

bool kdbus_item_in_message(struct kdbus_msg *msg, uint64_t type)
{
	const struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == type)
			return true;

	return false;
}

int kdbus_bus_creator_info(struct kdbus_conn *conn,
			   uint64_t flags,
			   uint64_t *offset)
{
	struct kdbus_cmd_info *cmd;
	size_t size = sizeof(*cmd);
	int ret;

	cmd = alloca(size);
	memset(cmd, 0, size);
	cmd->size = size;
	cmd->flags = flags;

	ret = kdbus_cmd_bus_creator_info(conn->fd, cmd);
	if (ret < 0) {
		kdbus_printf("--- error when requesting info: %d (%m)\n", ret);
		return ret;
	}

	if (offset)
		*offset = cmd->offset;
	else
		kdbus_free(conn, cmd->offset);

	return 0;
}

int kdbus_conn_info(struct kdbus_conn *conn, uint64_t id,
		    const char *name, uint64_t flags,
		    uint64_t *offset)
{
	struct kdbus_cmd_info *cmd;
	size_t size = sizeof(*cmd);
	struct kdbus_info *info;
	int ret;

	if (name)
		size += KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;

	cmd = alloca(size);
	memset(cmd, 0, size);
	cmd->size = size;
	cmd->flags = flags;

	if (name) {
		cmd->items[0].size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
		cmd->items[0].type = KDBUS_ITEM_NAME;
		strcpy(cmd->items[0].str, name);
	} else {
		cmd->id = id;
	}

	ret = kdbus_cmd_conn_info(conn->fd, cmd);
	if (ret < 0) {
		kdbus_printf("--- error when requesting info: %d (%m)\n", ret);
		return ret;
	}

	info = (struct kdbus_info *) (conn->buf + cmd->offset);
	if (info->size != cmd->info_size) {
		kdbus_printf("%s(): size mismatch: %d != %d\n", __func__,
				(int) info->size, (int) cmd->info_size);
		return -EIO;
	}

	if (offset)
		*offset = cmd->offset;
	else
		kdbus_free(conn, cmd->offset);

	return 0;
}

void kdbus_conn_free(struct kdbus_conn *conn)
{
	if (!conn)
		return;

	if (conn->buf)
		munmap(conn->buf, POOL_SIZE);

	if (conn->fd >= 0)
		close(conn->fd);

	free(conn);
}

int sys_memfd_create(const char *name, __u64 size)
{
	int ret, fd;

	ret = syscall(__NR_memfd_create, name, MFD_ALLOW_SEALING);
	if (ret < 0)
		return ret;

	fd = ret;

	ret = ftruncate(fd, size);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	return fd;
}

int sys_memfd_seal_set(int fd)
{
	return fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK |
			 F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
}

off_t sys_memfd_get_size(int fd, off_t *size)
{
	struct stat stat;
	int ret;

	ret = fstat(fd, &stat);
	if (ret < 0) {
		kdbus_printf("stat() failed: %m\n");
		return ret;
	}

	*size = stat.st_size;
	return 0;
}

static int __kdbus_msg_send(const struct kdbus_conn *conn,
			    const char *name,
			    uint64_t cookie,
			    uint64_t flags,
			    uint64_t timeout,
			    int64_t priority,
			    uint64_t dst_id,
			    uint64_t cmd_flags,
			    int cancel_fd)
{
	struct kdbus_cmd_send *cmd;
	struct kdbus_msg *msg;
	const char ref1[1024 * 128 + 3] = "0123456789_0";
	const char ref2[] = "0123456789_1";
	struct kdbus_item *item;
	struct timespec now;
	uint64_t size;
	int memfd = -1;
	int ret;

	size = sizeof(*msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	if (dst_id == KDBUS_DST_ID_BROADCAST)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + 64;
	else {
		memfd = sys_memfd_create("my-name-is-nice", 1024 * 1024);
		if (memfd < 0) {
			kdbus_printf("failed to create memfd: %m\n");
			return memfd;
		}

		if (write(memfd, "kdbus memfd 1234567", 19) != 19) {
			ret = -errno;
			kdbus_printf("writing to memfd failed: %m\n");
			return ret;
		}

		ret = sys_memfd_seal_set(memfd);
		if (ret < 0) {
			ret = -errno;
			kdbus_printf("memfd sealing failed: %m\n");
			return ret;
		}

		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
	}

	if (name)
		size += KDBUS_ITEM_SIZE(strlen(name) + 1);

	msg = malloc(size);
	if (!msg) {
		ret = -errno;
		kdbus_printf("unable to malloc()!?\n");
		return ret;
	}

	if (dst_id == KDBUS_DST_ID_BROADCAST)
		flags |= KDBUS_MSG_SIGNAL;

	memset(msg, 0, size);
	msg->flags = flags;
	msg->priority = priority;
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = name ? 0 : dst_id;
	msg->cookie = cookie;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	if (timeout) {
		ret = clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
		if (ret < 0)
			return ret;

		msg->timeout_ns = now.tv_sec * 1000000000ULL +
				  now.tv_nsec + timeout;
	}

	item = msg->items;

	if (name) {
		item->type = KDBUS_ITEM_DST_NAME;
		item->size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
		strcpy(item->str, name);
		item = KDBUS_ITEM_NEXT(item);
	}

	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)&ref1;
	item->vec.size = sizeof(ref1);
	item = KDBUS_ITEM_NEXT(item);

	/* data padding for ref1 */
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)NULL;
	item->vec.size =  KDBUS_ALIGN8(sizeof(ref1)) - sizeof(ref1);
	item = KDBUS_ITEM_NEXT(item);

	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)&ref2;
	item->vec.size = sizeof(ref2);
	item = KDBUS_ITEM_NEXT(item);

	if (dst_id == KDBUS_DST_ID_BROADCAST) {
		item->type = KDBUS_ITEM_BLOOM_FILTER;
		item->size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter)) + 64;
		item->bloom_filter.generation = 0;
	} else {
		item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
		item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_memfd);
		item->memfd.size = 16;
		item->memfd.fd = memfd;
	}
	item = KDBUS_ITEM_NEXT(item);

	size = sizeof(*cmd);
	if (cancel_fd != -1)
		size += KDBUS_ITEM_SIZE(sizeof(cancel_fd));

	cmd = malloc(size);
	cmd->size = size;
	cmd->flags = cmd_flags;
	cmd->msg_address = (uintptr_t)msg;

	item = cmd->items;

	if (cancel_fd != -1) {
		item->type = KDBUS_ITEM_CANCEL_FD;
		item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(cancel_fd);
		item->fds[0] = cancel_fd;
		item = KDBUS_ITEM_NEXT(item);
	}

	ret = kdbus_cmd_send(conn->fd, cmd);
	if (memfd >= 0)
		close(memfd);

	if (ret < 0) {
		kdbus_printf("error sending message: %d (%m)\n", ret);
		return ret;
	}

	if (cmd_flags & KDBUS_SEND_SYNC_REPLY) {
		struct kdbus_msg *reply;

		kdbus_printf("SYNC REPLY @offset %llu:\n", cmd->reply.offset);
		reply = (struct kdbus_msg *)(conn->buf + cmd->reply.offset);
		kdbus_msg_dump(conn, reply);

		kdbus_msg_free(reply);

		ret = kdbus_free(conn, cmd->reply.offset);
		if (ret < 0)
			return ret;
	}

	free(msg);
	free(cmd);

	return 0;
}

int kdbus_msg_send(const struct kdbus_conn *conn, const char *name,
		   uint64_t cookie, uint64_t flags, uint64_t timeout,
		   int64_t priority, uint64_t dst_id)
{
	return __kdbus_msg_send(conn, name, cookie, flags, timeout, priority,
				dst_id, 0, -1);
}

int kdbus_msg_send_sync(const struct kdbus_conn *conn, const char *name,
			uint64_t cookie, uint64_t flags, uint64_t timeout,
			int64_t priority, uint64_t dst_id, int cancel_fd)
{
	return __kdbus_msg_send(conn, name, cookie, flags, timeout, priority,
				dst_id, KDBUS_SEND_SYNC_REPLY, cancel_fd);
}

int kdbus_msg_send_reply(const struct kdbus_conn *conn,
			 uint64_t reply_cookie,
			 uint64_t dst_id)
{
	struct kdbus_cmd_send cmd = {};
	struct kdbus_msg *msg;
	const char ref1[1024 * 128 + 3] = "0123456789_0";
	struct kdbus_item *item;
	uint64_t size;
	int ret;

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	msg = malloc(size);
	if (!msg) {
		kdbus_printf("unable to malloc()!?\n");
		return -ENOMEM;
	}

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = dst_id;
	msg->cookie_reply = reply_cookie;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	item = msg->items;

	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)&ref1;
	item->vec.size = sizeof(ref1);
	item = KDBUS_ITEM_NEXT(item);

	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	ret = kdbus_cmd_send(conn->fd, &cmd);
	if (ret < 0)
		kdbus_printf("error sending message: %d (%m)\n", ret);

	free(msg);

	return ret;
}

static char *msg_id(uint64_t id, char *buf)
{
	if (id == 0)
		return "KERNEL";
	if (id == ~0ULL)
		return "BROADCAST";
	sprintf(buf, "%llu", (unsigned long long)id);
	return buf;
}

int kdbus_msg_dump(const struct kdbus_conn *conn, const struct kdbus_msg *msg)
{
	const struct kdbus_item *item = msg->items;
	char buf_src[32];
	char buf_dst[32];
	uint64_t timeout = 0;
	uint64_t cookie_reply = 0;
	int ret = 0;

	if (msg->flags & KDBUS_MSG_EXPECT_REPLY)
		timeout = msg->timeout_ns;
	else
		cookie_reply = msg->cookie_reply;

	kdbus_printf("MESSAGE: %s (%llu bytes) flags=0x%08llx, %s → %s, "
		     "cookie=%llu, timeout=%llu cookie_reply=%llu priority=%lli\n",
		enum_PAYLOAD(msg->payload_type), (unsigned long long)msg->size,
		(unsigned long long)msg->flags,
		msg_id(msg->src_id, buf_src), msg_id(msg->dst_id, buf_dst),
		(unsigned long long)msg->cookie, (unsigned long long)timeout,
		(unsigned long long)cookie_reply, (long long)msg->priority);

	KDBUS_ITEM_FOREACH(item, msg, items) {
		if (item->size < KDBUS_ITEM_HEADER_SIZE) {
			kdbus_printf("  +%s (%llu bytes) invalid data record\n",
				     enum_MSG(item->type), item->size);
			ret = -EINVAL;
			break;
		}

		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_OFF: {
			char *s;

			if (item->vec.offset == ~0ULL)
				s = "[\\0-bytes]";
			else
				s = (char *)conn->buf + item->vec.offset;

			kdbus_printf("  +%s (%llu bytes) off=%llu size=%llu '%s'\n",
			       enum_MSG(item->type), item->size,
			       (unsigned long long)item->vec.offset,
			       (unsigned long long)item->vec.size, s);
			break;
		}

		case KDBUS_ITEM_FDS: {
			int i, n = (item->size - KDBUS_ITEM_HEADER_SIZE) /
					sizeof(int);

			kdbus_printf("  +%s (%llu bytes, %d fds)\n",
			       enum_MSG(item->type), item->size, n);

			for (i = 0; i < n; i++)
				kdbus_printf("    fd[%d] = %d\n",
					     i, item->fds[i]);

			break;
		}

		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			char *buf;
			off_t size;

			buf = mmap(NULL, item->memfd.size, PROT_READ,
				   MAP_SHARED, item->memfd.fd, 0);
			if (buf == MAP_FAILED) {
				kdbus_printf("mmap() fd=%i size=%llu failed: %m\n",
					     item->memfd.fd, item->memfd.size);
				break;
			}

			if (sys_memfd_get_size(item->memfd.fd, &size) < 0) {
				kdbus_printf("KDBUS_CMD_MEMFD_SIZE_GET failed: %m\n");
				break;
			}

			kdbus_printf("  +%s (%llu bytes) fd=%i size=%llu filesize=%llu '%s'\n",
			       enum_MSG(item->type), item->size, item->memfd.fd,
			       (unsigned long long)item->memfd.size,
			       (unsigned long long)size, buf);
			munmap(buf, item->memfd.size);
			break;
		}

		case KDBUS_ITEM_CREDS:
			kdbus_printf("  +%s (%llu bytes) uid=%d, euid=%d, suid=%d, fsuid=%d, "
							"gid=%d, egid=%d, sgid=%d, fsgid=%d\n",
				enum_MSG(item->type), item->size,
				item->creds.uid, item->creds.euid,
				item->creds.suid, item->creds.fsuid,
				item->creds.gid, item->creds.egid,
				item->creds.sgid, item->creds.fsgid);
			break;

		case KDBUS_ITEM_PIDS:
			kdbus_printf("  +%s (%llu bytes) pid=%lld, tid=%lld, ppid=%lld\n",
				enum_MSG(item->type), item->size,
				item->pids.pid, item->pids.tid,
				item->pids.ppid);
			break;

		case KDBUS_ITEM_AUXGROUPS: {
			int i, n;

			kdbus_printf("  +%s (%llu bytes)\n",
				     enum_MSG(item->type), item->size);
			n = (item->size - KDBUS_ITEM_HEADER_SIZE) /
				sizeof(uint32_t);

			for (i = 0; i < n; i++)
				kdbus_printf("    gid[%d] = %d\n",
					     i, item->data32[i]);
			break;
		}

		case KDBUS_ITEM_NAME:
		case KDBUS_ITEM_PID_COMM:
		case KDBUS_ITEM_TID_COMM:
		case KDBUS_ITEM_EXE:
		case KDBUS_ITEM_CGROUP:
		case KDBUS_ITEM_SECLABEL:
		case KDBUS_ITEM_DST_NAME:
		case KDBUS_ITEM_CONN_DESCRIPTION:
			kdbus_printf("  +%s (%llu bytes) '%s' (%zu)\n",
				     enum_MSG(item->type), item->size,
				     item->str, strlen(item->str));
			break;

		case KDBUS_ITEM_OWNED_NAME: {
			kdbus_printf("  +%s (%llu bytes) '%s' (%zu) flags=0x%08llx\n",
				     enum_MSG(item->type), item->size,
				     item->name.name, strlen(item->name.name),
				     item->name.flags);
			break;
		}

		case KDBUS_ITEM_CMDLINE: {
			size_t size = item->size - KDBUS_ITEM_HEADER_SIZE;
			const char *str = item->str;
			int count = 0;

			kdbus_printf("  +%s (%llu bytes) ",
				     enum_MSG(item->type), item->size);
			while (size) {
				kdbus_printf("'%s' ", str);
				size -= strlen(str) + 1;
				str += strlen(str) + 1;
				count++;
			}

			kdbus_printf("(%d string%s)\n",
				     count, (count == 1) ? "" : "s");
			break;
		}

		case KDBUS_ITEM_AUDIT:
			kdbus_printf("  +%s (%llu bytes) loginuid=%u sessionid=%u\n",
			       enum_MSG(item->type), item->size,
			       item->audit.loginuid, item->audit.sessionid);
			break;

		case KDBUS_ITEM_CAPS: {
			const uint32_t *cap;
			int n, i;

			kdbus_printf("  +%s (%llu bytes) len=%llu bytes, last_cap %d\n",
				     enum_MSG(item->type), item->size,
				     (unsigned long long)item->size -
					KDBUS_ITEM_HEADER_SIZE,
				     (int) item->caps.last_cap);

			cap = item->caps.caps;
			n = (item->size - offsetof(struct kdbus_item, caps.caps))
				/ 4 / sizeof(uint32_t);

			kdbus_printf("    CapInh=");
			for (i = 0; i < n; i++)
				kdbus_printf("%08x", cap[(0 * n) + (n - i - 1)]);

			kdbus_printf(" CapPrm=");
			for (i = 0; i < n; i++)
				kdbus_printf("%08x", cap[(1 * n) + (n - i - 1)]);

			kdbus_printf(" CapEff=");
			for (i = 0; i < n; i++)
				kdbus_printf("%08x", cap[(2 * n) + (n - i - 1)]);

			kdbus_printf(" CapBnd=");
			for (i = 0; i < n; i++)
				kdbus_printf("%08x", cap[(3 * n) + (n - i - 1)]);
			kdbus_printf("\n");
			break;
		}

		case KDBUS_ITEM_TIMESTAMP:
			kdbus_printf("  +%s (%llu bytes) seq=%llu realtime=%lluns monotonic=%lluns\n",
			       enum_MSG(item->type), item->size,
			       (unsigned long long)item->timestamp.seqnum,
			       (unsigned long long)item->timestamp.realtime_ns,
			       (unsigned long long)item->timestamp.monotonic_ns);
			break;

		case KDBUS_ITEM_REPLY_TIMEOUT:
			kdbus_printf("  +%s (%llu bytes) cookie=%llu\n",
			       enum_MSG(item->type), item->size,
			       msg->cookie_reply);
			break;

		case KDBUS_ITEM_NAME_ADD:
		case KDBUS_ITEM_NAME_REMOVE:
		case KDBUS_ITEM_NAME_CHANGE:
			kdbus_printf("  +%s (%llu bytes) '%s', old id=%lld, now id=%lld, old_flags=0x%llx new_flags=0x%llx\n",
				enum_MSG(item->type),
				(unsigned long long) item->size,
				item->name_change.name,
				item->name_change.old_id.id,
				item->name_change.new_id.id,
				item->name_change.old_id.flags,
				item->name_change.new_id.flags);
			break;

		case KDBUS_ITEM_ID_ADD:
		case KDBUS_ITEM_ID_REMOVE:
			kdbus_printf("  +%s (%llu bytes) id=%llu flags=%llu\n",
			       enum_MSG(item->type),
			       (unsigned long long) item->size,
			       (unsigned long long) item->id_change.id,
			       (unsigned long long) item->id_change.flags);
			break;

		default:
			kdbus_printf("  +%s (%llu bytes)\n",
				     enum_MSG(item->type), item->size);
			break;
		}
	}

	if ((char *)item - ((char *)msg + msg->size) >= 8) {
		kdbus_printf("invalid padding at end of message\n");
		ret = -EINVAL;
	}

	kdbus_printf("\n");

	return ret;
}

void kdbus_msg_free(struct kdbus_msg *msg)
{
	const struct kdbus_item *item;
	int nfds, i;

	if (!msg)
		return;

	KDBUS_ITEM_FOREACH(item, msg, items) {
		switch (item->type) {
		/* close all memfds */
		case KDBUS_ITEM_PAYLOAD_MEMFD:
			close(item->memfd.fd);
			break;
		case KDBUS_ITEM_FDS:
			nfds = (item->size - KDBUS_ITEM_HEADER_SIZE) /
				sizeof(int);

			for (i = 0; i < nfds; i++)
				close(item->fds[i]);

			break;
		}
	}
}

int kdbus_msg_recv(struct kdbus_conn *conn,
		   struct kdbus_msg **msg_out,
		   uint64_t *offset)
{
	struct kdbus_cmd_recv recv = { .size = sizeof(recv) };
	struct kdbus_msg *msg;
	int ret;

	ret = kdbus_cmd_recv(conn->fd, &recv);
	if (ret < 0) {
		/* store how many lost packets */
		if (ret == -EOVERFLOW && offset)
			*offset = recv.dropped_msgs;

		return ret;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.msg.offset);
	ret = kdbus_msg_dump(conn, msg);
	if (ret < 0) {
		kdbus_msg_free(msg);
		return ret;
	}

	if (msg_out) {
		*msg_out = msg;

		if (offset)
			*offset = recv.msg.offset;
	} else {
		kdbus_msg_free(msg);

		ret = kdbus_free(conn, recv.msg.offset);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * Returns: 0 on success, negative errno on failure.
 *
 * We must return -ETIMEDOUT, -ECONNREST, -EAGAIN and other errors.
 * We must return the result of kdbus_msg_recv()
 */
int kdbus_msg_recv_poll(struct kdbus_conn *conn,
			int timeout_ms,
			struct kdbus_msg **msg_out,
			uint64_t *offset)
{
	int ret;

	do {
		struct timeval before, after, diff;
		struct pollfd fd;

		fd.fd = conn->fd;
		fd.events = POLLIN | POLLPRI | POLLHUP;
		fd.revents = 0;

		gettimeofday(&before, NULL);
		ret = poll(&fd, 1, timeout_ms);
		gettimeofday(&after, NULL);

		if (ret == 0) {
			ret = -ETIMEDOUT;
			break;
		}

		if (ret > 0) {
			if (fd.revents & POLLIN)
				ret = kdbus_msg_recv(conn, msg_out, offset);

			if (fd.revents & (POLLHUP | POLLERR))
				ret = -ECONNRESET;
		}

		if (ret == 0 || ret != -EAGAIN)
			break;

		timersub(&after, &before, &diff);
		timeout_ms -= diff.tv_sec * 1000UL +
			      diff.tv_usec / 1000UL;
	} while (timeout_ms > 0);

	return ret;
}

int kdbus_free(const struct kdbus_conn *conn, uint64_t offset)
{
	struct kdbus_cmd_free cmd_free = {};
	int ret;

	cmd_free.size = sizeof(cmd_free);
	cmd_free.offset = offset;
	cmd_free.flags = 0;

	ret = kdbus_cmd_free(conn->fd, &cmd_free);
	if (ret < 0) {
		kdbus_printf("KDBUS_CMD_FREE failed: %d (%m)\n", ret);
		return ret;
	}

	return 0;
}

int kdbus_name_acquire(struct kdbus_conn *conn,
		       const char *name, uint64_t *flags)
{
	struct kdbus_cmd *cmd_name;
	size_t name_len = strlen(name) + 1;
	uint64_t size = sizeof(*cmd_name) + KDBUS_ITEM_SIZE(name_len);
	struct kdbus_item *item;
	int ret;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);

	item = cmd_name->items;
	item->size = KDBUS_ITEM_HEADER_SIZE + name_len;
	item->type = KDBUS_ITEM_NAME;
	strcpy(item->str, name);

	cmd_name->size = size;
	if (flags)
		cmd_name->flags = *flags;

	ret = kdbus_cmd_name_acquire(conn->fd, cmd_name);
	if (ret < 0) {
		kdbus_printf("error aquiring name: %s\n", strerror(-ret));
		return ret;
	}

	kdbus_printf("%s(): flags after call: 0x%llx\n", __func__,
		     cmd_name->flags);

	if (flags)
		*flags = cmd_name->flags;

	return 0;
}

int kdbus_name_release(struct kdbus_conn *conn, const char *name)
{
	struct kdbus_cmd *cmd_name;
	size_t name_len = strlen(name) + 1;
	uint64_t size = sizeof(*cmd_name) + KDBUS_ITEM_SIZE(name_len);
	struct kdbus_item *item;
	int ret;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);

	item = cmd_name->items;
	item->size = KDBUS_ITEM_HEADER_SIZE + name_len;
	item->type = KDBUS_ITEM_NAME;
	strcpy(item->str, name);

	cmd_name->size = size;

	kdbus_printf("conn %lld giving up name '%s'\n",
		     (unsigned long long) conn->id, name);

	ret = kdbus_cmd_name_release(conn->fd, cmd_name);
	if (ret < 0) {
		kdbus_printf("error releasing name: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

int kdbus_list(struct kdbus_conn *conn, uint64_t flags)
{
	struct kdbus_cmd_list cmd_list = {};
	struct kdbus_info *list, *name;
	int ret;

	cmd_list.size = sizeof(cmd_list);
	cmd_list.flags = flags;

	ret = kdbus_cmd_list(conn->fd, &cmd_list);
	if (ret < 0) {
		kdbus_printf("error listing names: %d (%m)\n", ret);
		return ret;
	}

	kdbus_printf("REGISTRY:\n");
	list = (struct kdbus_info *)(conn->buf + cmd_list.offset);

	KDBUS_FOREACH(name, list, cmd_list.list_size) {
		uint64_t flags = 0;
		struct kdbus_item *item;
		const char *n = "MISSING-NAME";

		if (name->size == sizeof(struct kdbus_cmd))
			continue;

		KDBUS_ITEM_FOREACH(item, name, items)
			if (item->type == KDBUS_ITEM_OWNED_NAME) {
				n = item->name.name;
				flags = item->name.flags;
			}

		kdbus_printf("%8llu flags=0x%08llx conn=0x%08llx '%s'\n",
			     name->id, (unsigned long long) flags,
			     name->flags, n);
	}
	kdbus_printf("\n");

	ret = kdbus_free(conn, cmd_list.offset);

	return ret;
}

int kdbus_conn_update_attach_flags(struct kdbus_conn *conn,
				   uint64_t attach_flags_send,
				   uint64_t attach_flags_recv)
{
	int ret;
	size_t size;
	struct kdbus_cmd *update;
	struct kdbus_item *item;

	size = sizeof(struct kdbus_cmd);
	size += KDBUS_ITEM_SIZE(sizeof(uint64_t)) * 2;

	update = malloc(size);
	if (!update) {
		kdbus_printf("error malloc: %d (%m)\n", ret);
		return -ENOMEM;
	}

	memset(update, 0, size);
	update->size = size;

	item = update->items;

	item->type = KDBUS_ITEM_ATTACH_FLAGS_SEND;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(uint64_t);
	item->data64[0] = attach_flags_send;
	item = KDBUS_ITEM_NEXT(item);

	item->type = KDBUS_ITEM_ATTACH_FLAGS_RECV;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(uint64_t);
	item->data64[0] = attach_flags_recv;
	item = KDBUS_ITEM_NEXT(item);

	ret = kdbus_cmd_update(conn->fd, update);
	if (ret < 0)
		kdbus_printf("error conn update: %d (%m)\n", ret);

	free(update);

	return ret;
}

int kdbus_conn_update_policy(struct kdbus_conn *conn, const char *name,
			     const struct kdbus_policy_access *access,
			     size_t num_access)
{
	struct kdbus_cmd *update;
	struct kdbus_item *item;
	size_t i, size;
	int ret;

	size = sizeof(struct kdbus_cmd);
	size += KDBUS_ITEM_SIZE(strlen(name) + 1);
	size += num_access * KDBUS_ITEM_SIZE(sizeof(struct kdbus_policy_access));

	update = malloc(size);
	if (!update) {
		kdbus_printf("error malloc: %d (%m)\n", ret);
		return -ENOMEM;
	}

	memset(update, 0, size);
	update->size = size;

	item = update->items;

	item->type = KDBUS_ITEM_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
	strcpy(item->str, name);
	item = KDBUS_ITEM_NEXT(item);

	for (i = 0; i < num_access; i++) {
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     sizeof(struct kdbus_policy_access);
		item->type = KDBUS_ITEM_POLICY_ACCESS;

		item->policy_access.type = access[i].type;
		item->policy_access.access = access[i].access;
		item->policy_access.id = access[i].id;

		item = KDBUS_ITEM_NEXT(item);
	}

	ret = kdbus_cmd_update(conn->fd, update);
	if (ret < 0)
		kdbus_printf("error conn update: %d (%m)\n", ret);

	free(update);

	return ret;
}

int kdbus_add_match_id(struct kdbus_conn *conn, uint64_t cookie,
		       uint64_t type, uint64_t id)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_notify_id_change chg;
		} item;
	} buf;
	int ret;

	memset(&buf, 0, sizeof(buf));

	buf.cmd.size = sizeof(buf);
	buf.cmd.cookie = cookie;
	buf.item.size = sizeof(buf.item);
	buf.item.type = type;
	buf.item.chg.id = id;

	ret = kdbus_cmd_match_add(conn->fd, &buf.cmd);
	if (ret < 0)
		kdbus_printf("--- error adding conn match: %d (%m)\n", ret);

	return ret;
}

int kdbus_add_match_empty(struct kdbus_conn *conn)
{
	struct {
		struct kdbus_cmd_match cmd;
		struct kdbus_item item;
	} buf;
	int ret;

	memset(&buf, 0, sizeof(buf));

	buf.item.size = sizeof(uint64_t) * 3;
	buf.item.type = KDBUS_ITEM_ID;
	buf.item.id = KDBUS_MATCH_ID_ANY;

	buf.cmd.size = sizeof(buf.cmd) + buf.item.size;

	ret = kdbus_cmd_match_add(conn->fd, &buf.cmd);
	if (ret < 0)
		kdbus_printf("--- error adding conn match: %d (%m)\n", ret);

	return ret;
}

static int all_ids_are_mapped(const char *path)
{
	int ret;
	FILE *file;
	uint32_t inside_id, length;

	file = fopen(path, "r");
	if (!file) {
		ret = -errno;
		kdbus_printf("error fopen() %s: %d (%m)\n",
			     path, ret);
		return ret;
	}

	ret = fscanf(file, "%u\t%*u\t%u", &inside_id, &length);
	if (ret != 2) {
		if (ferror(file))
			ret = -errno;
		else
			ret = -EIO;

		kdbus_printf("--- error fscanf(): %d\n", ret);
		fclose(file);
		return ret;
	}

	fclose(file);

	/*
	 * If length is 4294967295 which means the invalid uid
	 * (uid_t) -1 then we are able to map all uid/gids
	 */
	if (inside_id == 0 && length == (uid_t) -1)
		return 1;

	return 0;
}

int all_uids_gids_are_mapped()
{
	int ret;

	ret = all_ids_are_mapped("/proc/self/uid_map");
	if (ret <= 0) {
		kdbus_printf("--- error not all uids are mapped\n");
		return 0;
	}

	ret = all_ids_are_mapped("/proc/self/gid_map");
	if (ret <= 0) {
		kdbus_printf("--- error not all gids are mapped\n");
		return 0;
	}

	return 1;
}

int drop_privileges(uid_t uid, gid_t gid)
{
	int ret;

	ret = setgroups(0, NULL);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error setgroups: %d (%m)\n", ret);
		return ret;
	}

	ret = setresgid(gid, gid, gid);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error setresgid: %d (%m)\n", ret);
		return ret;
	}

	ret = setresuid(uid, uid, uid);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error setresuid: %d (%m)\n", ret);
		return ret;
	}

	return ret;
}

uint64_t now(clockid_t clock)
{
	struct timespec spec;

	clock_gettime(clock, &spec);
	return spec.tv_sec * 1000ULL * 1000ULL * 1000ULL + spec.tv_nsec;
}

char *unique_name(const char *prefix)
{
	unsigned int i;
	uint64_t u_now;
	char n[17];
	char *str;
	int r;

	/*
	 * This returns a random string which is guaranteed to be
	 * globally unique across all calls to unique_name(). We
	 * compose the string as:
	 *   <prefix>-<random>-<time>
	 * With:
	 *   <prefix>: string provided by the caller
	 *   <random>: a random alpha string of 16 characters
	 *   <time>: the current time in micro-seconds since last boot
	 *
	 * The <random> part makes the string always look vastly different,
	 * the <time> part makes sure no two calls return the same string.
	 */

	u_now = now(CLOCK_MONOTONIC);

	for (i = 0; i < sizeof(n) - 1; ++i)
		n[i] = 'a' + (rand() % ('z' - 'a'));
	n[sizeof(n) - 1] = 0;

	r = asprintf(&str, "%s-%s-%" PRIu64, prefix, n, u_now);
	if (r < 0)
		return NULL;

	return str;
}

static int do_userns_map_id(pid_t pid,
			    const char *map_file,
			    const char *map_id)
{
	int ret;
	int fd;
	char *map;
	unsigned int i;

	map = strndupa(map_id, strlen(map_id));
	if (!map) {
		ret = -errno;
		kdbus_printf("error strndupa %s: %d (%m)\n",
			map_file, ret);
		return ret;
	}

	for (i = 0; i < strlen(map); i++)
		if (map[i] == ',')
			map[i] = '\n';

	fd = open(map_file, O_RDWR);
	if (fd < 0) {
		ret = -errno;
		kdbus_printf("error open %s: %d (%m)\n",
			map_file, ret);
		return ret;
	}

	ret = write(fd, map, strlen(map));
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error write to %s: %d (%m)\n",
			     map_file, ret);
		goto out;
	}

	ret = 0;

out:
	close(fd);
	return ret;
}

int userns_map_uid_gid(pid_t pid,
		       const char *map_uid,
		       const char *map_gid)
{
	int fd, ret;
	char file_id[128] = {'\0'};

	snprintf(file_id, sizeof(file_id), "/proc/%ld/uid_map",
		 (long) pid);

	ret = do_userns_map_id(pid, file_id, map_uid);
	if (ret < 0)
		return ret;

	snprintf(file_id, sizeof(file_id), "/proc/%ld/setgroups",
		 (long) pid);

	fd = open(file_id, O_WRONLY);
	if (fd >= 0) {
		write(fd, "deny\n", 5);
		close(fd);
	}

	snprintf(file_id, sizeof(file_id), "/proc/%ld/gid_map",
		 (long) pid);

	return do_userns_map_id(pid, file_id, map_gid);
}

static int do_cap_get_flag(cap_t caps, cap_value_t cap)
{
	int ret;
	cap_flag_value_t flag_set;

	ret = cap_get_flag(caps, cap, CAP_EFFECTIVE, &flag_set);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error cap_get_flag(): %d (%m)\n", ret);
		return ret;
	}

	return (flag_set == CAP_SET);
}

/*
 * Returns:
 *  1 in case all the requested effective capabilities are set.
 *  0 in case we do not have the requested capabilities. This value
 *    will be used to abort tests with TEST_SKIP
 *  Negative errno on failure.
 *
 *  Terminate args with a negative value.
 */
int test_is_capable(int cap, ...)
{
	int ret;
	va_list ap;
	cap_t caps;

	caps = cap_get_proc();
	if (!cap) {
		ret = -errno;
		kdbus_printf("error cap_get_proc(): %d (%m)\n", ret);
		return ret;
	}

	ret = do_cap_get_flag(caps, (cap_value_t)cap);
	if (ret <= 0)
		goto out;

	va_start(ap, cap);
	while ((cap = va_arg(ap, int)) > 0) {
		ret = do_cap_get_flag(caps, (cap_value_t)cap);
		if (ret <= 0)
			break;
	}
	va_end(ap);

out:
	cap_free(caps);
	return ret;
}

int config_user_ns_is_enabled(void)
{
	return (access("/proc/self/uid_map", F_OK) == 0);
}

int config_auditsyscall_is_enabled(void)
{
	return (access("/proc/self/loginuid", F_OK) == 0);
}

int config_cgroups_is_enabled(void)
{
	return (access("/proc/self/cgroup", F_OK) == 0);
}

int config_security_is_enabled(void)
{
	int fd;
	int ret;
	char buf[128];

	/* CONFIG_SECURITY is disabled */
	if (access("/proc/self/attr/current", F_OK) != 0)
		return 0;

	/*
	 * Now only if read() fails with -EINVAL then we assume
	 * that SECLABEL and LSM are disabled
	 */
	fd = open("/proc/self/attr/current", O_RDONLY|O_CLOEXEC);
	if (fd < 0)
		return 1;

	ret = read(fd, buf, sizeof(buf));
	if (ret == -1 && errno == EINVAL)
		ret = 0;
	else
		ret = 1;

	close(fd);

	return ret;
}
