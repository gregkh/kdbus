/*
 * Copyright (C) 2013 Kay Sievers
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
#include <sys/ioctl.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

struct kdbus_enum_table {
	long long id;
	const char *name;
};

#define TABLE(what) static struct kdbus_enum_table kdbus_table_##what[]
#define ENUM(_id) { .id=_id, .name=STRINGIFY(_id) }
#define LOOKUP(what)								\
	const char *enum_##what(long long id) {					\
		for (size_t i = 0; i < ELEMENTSOF(kdbus_table_##what); i++)	\
			if (id == kdbus_table_##what[i].id)			\
				return kdbus_table_##what[i].name;		\
		return "UNKNOWN";						\
	}

TABLE(CMD) = {
	ENUM(KDBUS_CMD_BUS_MAKE),
	ENUM(KDBUS_CMD_NS_MAKE),
	ENUM(KDBUS_CMD_EP_MAKE),
	ENUM(KDBUS_CMD_HELLO),
	ENUM(KDBUS_CMD_MSG_SEND),
	ENUM(KDBUS_CMD_MSG_RECV),
	ENUM(KDBUS_CMD_NAME_ACQUIRE),
	ENUM(KDBUS_CMD_NAME_RELEASE),
	ENUM(KDBUS_CMD_NAME_LIST),
	ENUM(KDBUS_CMD_NAME_QUERY),
	ENUM(KDBUS_CMD_MATCH_ADD),
	ENUM(KDBUS_CMD_MATCH_REMOVE),
	ENUM(KDBUS_CMD_MONITOR),
	ENUM(KDBUS_CMD_EP_POLICY_SET),
};
LOOKUP(CMD);

TABLE(MSG) = {
	ENUM(_KDBUS_MSG_NULL),
	ENUM(KDBUS_MSG_PAYLOAD_VEC),
	ENUM(KDBUS_MSG_PAYLOAD_MEMFD),
	ENUM(KDBUS_MSG_FDS),
	ENUM(KDBUS_MSG_BLOOM),
	ENUM(KDBUS_MSG_DST_NAME),
	ENUM(KDBUS_MSG_SRC_CREDS),
	ENUM(KDBUS_MSG_SRC_PID_COMM),
	ENUM(KDBUS_MSG_SRC_TID_COMM),
	ENUM(KDBUS_MSG_SRC_EXE),
	ENUM(KDBUS_MSG_SRC_CMDLINE),
	ENUM(KDBUS_MSG_SRC_CGROUP),
	ENUM(KDBUS_MSG_SRC_CAPS),
	ENUM(KDBUS_MSG_SRC_SECLABEL),
	ENUM(KDBUS_MSG_SRC_AUDIT),
	ENUM(KDBUS_MSG_SRC_NAMES),
	ENUM(KDBUS_MSG_TIMESTAMP),
	ENUM(KDBUS_MSG_NAME_ADD),
	ENUM(KDBUS_MSG_NAME_REMOVE),
	ENUM(KDBUS_MSG_NAME_CHANGE),
	ENUM(KDBUS_MSG_ID_ADD),
	ENUM(KDBUS_MSG_ID_REMOVE),
	ENUM(KDBUS_MSG_REPLY_TIMEOUT),
	ENUM(KDBUS_MSG_REPLY_DEAD),
};
LOOKUP(MSG);

TABLE(MATCH) = {
	ENUM(_KDBUS_MATCH_NULL),
	ENUM(KDBUS_MATCH_BLOOM),
	ENUM(KDBUS_MATCH_SRC_NAME),
	ENUM(KDBUS_MATCH_NAME_ADD),
	ENUM(KDBUS_MATCH_NAME_REMOVE),
	ENUM(KDBUS_MATCH_NAME_CHANGE),
	ENUM(KDBUS_MATCH_ID_ADD),
	ENUM(KDBUS_MATCH_ID_REMOVE),
};
LOOKUP(MATCH);

TABLE(PAYLOAD) = {
	ENUM(_KDBUS_PAYLOAD_NULL),
	ENUM(KDBUS_PAYLOAD_DBUS1),
	ENUM(KDBUS_PAYLOAD_GVARIANT),
};
LOOKUP(PAYLOAD);
