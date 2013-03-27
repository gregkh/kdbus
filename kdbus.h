/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 */

#ifndef _KDBUS_H_
#define _KDBUS_H_

/* FIXME: move to include/uapi/linux/major.h */
#define KDBUS_CHAR_MAJOR	222

#define KDBUS_IOC_MAGIC		0x95

/* kdbus control device commands */
struct kdbus_cmd_fname {
	mode_t mode;
	char name[128];
};

enum kdbus_msg_data_type {
	/* Filled in by userspace */
	KDBUS_MSG_PAYLOAD,
	KDBUS_MSG_PAYLOAD_REF,
	KDBUS_MSG_UNIX_FDS,
	KDBUS_MSG_BLOOM,		/* Only filled in for broadcasts */
	KDBUS_MSG_DST_NAME,		/* Used only when destination is well-known name */

	/* Filled in by kernelspace */
	KDBUS_MSG_SRC_CAPS,
	KDBUS_MSG_SRC_SECLABEL,
	KDBUS_MSG_SRC_AUDIT,
	KDBUS_MSG_SRC_NAMES,
	KDBUS_MSG_DST_NAMES,
	KDBUS_MSG_KERNEL,
};

/**
 * struct  kdbus_msg_data - chain of data blocks
 *
 * size: overall data record size
 * type: kdbus_msg_data_type of data
 */
struct kdbus_msg_data {
	uint64_t size;
	uint32_t type;
	uint32_t reserved;
	union {
		uint8_t data[0];
		struct {
			uint64_t address;
			uint64_t size;
		} payload_ref;
	};
};

enum kdbus_msg_flags {
	EXPECT_REPLY = 1,
};

enum kdbus_manager_msg_type {
	KDBUS_NAME_CHANGE,   	uint64_t old_id, new_id, char[] name
	KDBUS_ID_NEW,		uint64_t id,
	KDBUS_ID_REMOVE,	uint64_t id,
	KDBUS_REPLY_TIMEOUT,
	KDBUS_REPLY_DEAD
};

/**
 * struct kdbus_msg
 *
 * set by userspace:
 * dst_id: destination id
 * data_size: overall message size
 * data: data for the message
 *
 * set by kernel:
 * id: message sequence number
 * src_id: who sent the message
 * src_uid: uid of sending process
 * src_pid: pid of sending process
 * src_tid: tid of sending process
 * ts_nsec: timestamp when message was sent to the kernel
 */
struct kdbus_msg {
	uint64_t data_size;
	uint64_t flags;
	uint64_t dst_id;	/* 0: well known name in data, -1: multicast, otherwise: unique name */
	uint64_t src_id;	/* 0: from kernel, otherwise: unique name */
	uint64_t serial;	/* userspace-supplied cookie */
	uint64_t serial_reply;	/* serial of msg this is a reply to */
	uint64_t payload_type;	/* 'DBUSDBUS', 'GVARIANT', ... */
	uint64_t src_uid;
	uint64_t src_gid;
	uint64_t src_pid;
	uint64_t src_tid;
	uint64_t ts_nsec;
	struct kdbus_msg_data data[0];
};

enum payload_type {
	KDBUS_PAYLOAD_DBUS1,
	KDBUS_PAYLOAD_GVARIANT,
};

struct kdbus_policy {
	uint64_t size;
	uint8_t type; /* NAME or ACCESS */
	uint8_t reserved[7];
	union {
		char name[0];
		struct {
			uint8_t type;  /* USER, GROUP, WORLD */
			uint8_t bits;  /* SEND, RECV, OWN */
			uint64_t id;   /* uid, gid, 0 */
		} access;
	}
};

struct kdbus_cmd_hello {
	/* userspace → kernel, kernel → userspace */
	uint64_t flags;

	/* kernel → userspace */
	uint64_t id;
};

enum {
	KDBUS_CMD_MATCH_BLOOM,
	KDBUS_CMD_DST_NAME,
	KDBUS_CMD_SRC_NAME
};

struct kdbus_cmd_match_item {
	uint8_t type;
	uint8_t data[0];
};

struct kdbus_cmd_match {
	uint64_t cookie; /* when adding: userspace sets arbitrary cookie; when removing; kernel deletes everything with same cookie */
	uint64_t src_id; /* -1: any. other: exact unique match */
	uint64_t dst_id; /* dito */
	struct kdbus_cmd_match_item  items[0];
};

enum {
	/* userspace → kernel */
	KDBUS_CMD_NAME_REPLACE_EXISTING = 1,
	KDBUS_CMD_NAME_QUEUE = 2,
	KDBUS_CMD_NAME_ALLOW_REPLACEMENT = 4,
	KDBUS_CMD_NAME_STARTER = 8,

	/* kernel → userspace */
	KDBUS_CMD_NAME_IN_QUEUE = 256,
}

struct kdbus_cmd_name {
	uint8_t flags;
	char name[256];
};

struct kdbus_cmd_names {
	uint64_t count;
	kdbus_cmd_name names[0];
};

enum {
	KDBUS_CMD_NAME_INFO_ITEM_SECLABEL,
	KDBUS_CMD_NAME_INFO_ITEM_AUDIT,
};

struct kdbus_cmd_name_info_item {
	uint64_t size;
	uint32_t type;
	uint32_t reserved;
	uint8_t data[0];
}

struct kdbus_cmd_name_info {
	uint64_t size;
	uint8_t flags;
	uint8_t reserved[7];
	uint64_t id;
	uint64_t pid;
	uint64_t tid;
	uint64_t uid;
	uint64_t gid;
	struct kdbus_cmd_name_info_item[0];
};

/* fd types
 *
 *	control nodes: 	unset
 *			bus owner  (via KDBUS_CMD_BUS_MAKE)
 *			ns owner   (via KDBUS_CMD_NS_MAKE)
 *	ep nodes:	unset
 *			connected  (via KDBUS_CMD_HELLO)
 *			ep owner   (via KDBUS_CMD_EP_MAKE)
*/

enum kdbus_cmd {
	/* kdbus control node commands: require unset state */
	KDBUS_CMD_BUS_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x00, struct kdbus_cmd_fname),
	KDBUS_CMD_NS_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x10, struct kdbus_cmd_fname),

	/* kdbus control node commands: require bus owner state */
	KDBUS_CMD_BUS_POLICY_SET =	_IOWR(KDBUS_IOC_MAGIC, 0x20, struct kdbus_cmd_policy),

	/* kdbus ep node commands: require unset state */
	KDBUS_CMD_EP_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x30, struct kdbus_cmd_fname),
	KDBUS_CMD_HELLO =		_IOWR(KDBUS_IOC_MAGIC, 0x31, struct kdbus_cmd_hello),

	/* kdbus ep node commands: require connected state */
	KDBUS_CMD_NAME_ACQUIRE =	_IOWR(KDBUS_IOC_MAGIC, 0x40, struct kdbus_cmd_name),
	KDBUS_CMD_NAME_RELEASE =	_IOWR(KDBUS_IOC_MAGIC, 0x41, struct kdbus_cmd_name),
	KDBUS_CMD_NAME_LIST =		_IOWR(KDBUS_IOC_MAGIC, 0x42, struct kdbus_cmd_names),
	KDBUS_CMD_NAME_QUERY =		_IOWR(KDBUS_IOC_MAGIC, 0x43, struct kdbus_cmd_name),

	KDBUS_CMD_MATCH_ADD =		_IOWR(KDBUS_IOC_MAGIC, 0x50, struct kdbus_cmd_match),
	KDBUS_CMD_MATCH_REMOVE =	_IOWR(KDBUS_IOC_MAGIC, 0x51, struct kdbus_cmd_match_info),

	KDBUS_CMD_MSG_SEND =		_IOWR(KDBUS_IOC_MAGIC, 0x60, struct kdbus_msg),
	KDBUS_CMD_MSG_RECV =		_IOWR(KDBUS_IOC_MAGIC, 0x61, struct kdbus_msg),

	/* kdbus ep node commands: require ep owner state */
	KDBUS_CMD_EP_POLICY_SET =	_IOWR(KDBUS_IOC_MAGIC, 0x70, struct kdbus_cmd_policy),
};

#endif
