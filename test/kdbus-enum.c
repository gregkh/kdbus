/*
 * Copyright (C) 2013-2015 Kay Sievers
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

struct kdbus_enum_table {
	long long id;
	const char *name;
};

#define TABLE(what) static struct kdbus_enum_table kdbus_table_##what[]
#define ENUM(_id) { .id = _id, .name = STRINGIFY(_id) }
#define LOOKUP(what)							\
	const char *enum_##what(long long id)				\
	{								\
		for (size_t i = 0; i < ELEMENTSOF(kdbus_table_##what); i++) \
			if (id == kdbus_table_##what[i].id)		\
				return kdbus_table_##what[i].name;	\
		return "UNKNOWN";					\
	}

TABLE(CMD) = {
	ENUM(KDBUS_CMD_BUS_MAKE),
	ENUM(KDBUS_CMD_ENDPOINT_MAKE),
	ENUM(KDBUS_CMD_HELLO),
	ENUM(KDBUS_CMD_SEND),
	ENUM(KDBUS_CMD_RECV),
	ENUM(KDBUS_CMD_LIST),
	ENUM(KDBUS_CMD_NAME_RELEASE),
	ENUM(KDBUS_CMD_CONN_INFO),
	ENUM(KDBUS_CMD_MATCH_ADD),
	ENUM(KDBUS_CMD_MATCH_REMOVE),
};
LOOKUP(CMD);

TABLE(MSG) = {
	ENUM(_KDBUS_ITEM_NULL),
	ENUM(KDBUS_ITEM_PAYLOAD_VEC),
	ENUM(KDBUS_ITEM_PAYLOAD_OFF),
	ENUM(KDBUS_ITEM_PAYLOAD_MEMFD),
	ENUM(KDBUS_ITEM_FDS),
	ENUM(KDBUS_ITEM_BLOOM_PARAMETER),
	ENUM(KDBUS_ITEM_BLOOM_FILTER),
	ENUM(KDBUS_ITEM_DST_NAME),
	ENUM(KDBUS_ITEM_MAKE_NAME),
	ENUM(KDBUS_ITEM_ATTACH_FLAGS_SEND),
	ENUM(KDBUS_ITEM_ATTACH_FLAGS_RECV),
	ENUM(KDBUS_ITEM_ID),
	ENUM(KDBUS_ITEM_NAME),
	ENUM(KDBUS_ITEM_TIMESTAMP),
	ENUM(KDBUS_ITEM_CREDS),
	ENUM(KDBUS_ITEM_PIDS),
	ENUM(KDBUS_ITEM_AUXGROUPS),
	ENUM(KDBUS_ITEM_OWNED_NAME),
	ENUM(KDBUS_ITEM_TID_COMM),
	ENUM(KDBUS_ITEM_PID_COMM),
	ENUM(KDBUS_ITEM_EXE),
	ENUM(KDBUS_ITEM_CMDLINE),
	ENUM(KDBUS_ITEM_CGROUP),
	ENUM(KDBUS_ITEM_CAPS),
	ENUM(KDBUS_ITEM_SECLABEL),
	ENUM(KDBUS_ITEM_AUDIT),
	ENUM(KDBUS_ITEM_CONN_DESCRIPTION),
	ENUM(KDBUS_ITEM_NAME_ADD),
	ENUM(KDBUS_ITEM_NAME_REMOVE),
	ENUM(KDBUS_ITEM_NAME_CHANGE),
	ENUM(KDBUS_ITEM_ID_ADD),
	ENUM(KDBUS_ITEM_ID_REMOVE),
	ENUM(KDBUS_ITEM_REPLY_TIMEOUT),
	ENUM(KDBUS_ITEM_REPLY_DEAD),
};
LOOKUP(MSG);

TABLE(PAYLOAD) = {
	ENUM(KDBUS_PAYLOAD_KERNEL),
	ENUM(KDBUS_PAYLOAD_DBUS),
};
LOOKUP(PAYLOAD);
