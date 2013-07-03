/*
 * Copyright (C) 2013 Kay Sievers
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */
#pragma once

#include "../kdbus.h"

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

#define KDBUS_PTR(addr) ((void *)(uintptr_t)(addr))

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_PART_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_PART_HEADER_SIZE)

#define KDBUS_PART_NEXT(part) \
	(typeof(part))(((uint8_t *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_PART_FOREACH(part, head, first)				\
	for (part = (head)->first;					\
	     (uint8_t *)(part) < (uint8_t *)(head) + (head)->size;	\
	     part = KDBUS_PART_NEXT(part))

struct conn {
	int fd;
	uint64_t id;
	void *buf;
	size_t size;
};

int name_list(struct conn *conn);
int name_release(struct conn *conn, const char *name);
int name_acquire(struct conn *conn, const char *name, uint64_t flags);
int msg_recv(struct conn *conn);
void msg_dump(const struct conn *conn, const struct kdbus_msg *msg);
char *msg_id(uint64_t id, char *buf);
int msg_send(const struct conn *conn, const char *name, uint64_t cookie, uint64_t dst_id);
struct conn *connect_to_bus(const char *path);
void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size);
struct kdbus_policy *make_policy_name(const char *name);
struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id);
int upload_policy(int fd);




