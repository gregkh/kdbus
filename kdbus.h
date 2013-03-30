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

#define KDBUS_WELL_KNOWN_NAME_LENGTH 256

/* Message sent from kernel to userspace, when the owner or starter of
 * a well-known name changes */
struct kdbus_manager_msg_name_change {
	char name[KDBUS_WELL_KNOWN_NAME_LENGTH];
	uint64_t old_id;
	uint64_t new_id;
	uint64_t flags;		/* 0, or KDBUS_CMD_NAME_STARTER, or (possibly?) KDBUS_CMD_NAME_IN_QUEUE */
};

struct kdbus_creds {
	uint64_t uid;
	uint64_t gid;
	uint64_t pid;
	uint64_t tid;

	/* The starttime of the process PID. This is useful to detect
	PID overruns from the client side. i.e. if you use the PID to
	look something up in /proc/$PID/ you can afterwards check the
	starttime field of it to ensure you didn't run into a PID
	overrun. */
	uint64_t starttime;
};

/* Message Data Types */
enum {
	/* Filled in by userspace */
	KDBUS_MSG_PAYLOAD,		/* Carries binary blob */
	KDBUS_MSG_PAYLOAD_REF,		/* Carries .ref */
	KDBUS_MSG_UNIX_FDS,		/* Carries int[] of file descriptors */
	KDBUS_MSG_BLOOM,		/* Only filled in for broadcasts, carries bloom filter blob */
	KDBUS_MSG_DST_NAME,		/* Used only when destination is well-known name */

	/* Filled in by kernelspace */
	KDBUS_MSG_SRC_CREDS,		/* Carries .creds */
	KDBUS_MSG_SRC_CAPS,		/* Carries caps blob */
	KDBUS_MSG_SRC_SECLABEL,		/* Carries NUL terminated string */
	KDBUS_MSG_SRC_AUDIT,		/* Carries array of two uint64_t of audit loginuid + sessiond */
	KDBUS_MSG_SRC_NAMES,		/* Carries concatenation of NUL terminated strings with all well-known names of source */
	KDBUS_MSG_DST_NAMES,		/* Carries concatenation of NUL terminated strings with all well-known names of destination */
	KDBUS_MSG_TIMESTAMP,		/* Carries uint64_t nsec timestamp of CLOCK_MONOTONIC */

	/* Special messages from kernel, consisting of one and only one of these data blocks */
	KDBUS_MSG_NAME_CHANGE,		/* Carries .name_change */
	KDBUS_MSG_ID_NEW,		/* Carries ID as uint64_t */
	KDBUS_MSG_ID_REMOVE,		/* Dito */
	KDBUS_MSG_REPLY_TIMEOUT,	/* Empty, only .reply_serial is relevant in the header */
	KDBUS_MSG_REPLY_DEAD,		/* Dito */
};

/**
 * struct  kdbus_msg_data - chain of data blocks
 *
 * size: overall data record size
 * type: kdbus_msg_data_type of data
 */
struct kdbus_msg_data {
	uint64_t size;
	uint64_t type;
	union {
		char data[0];
		uint32_t data_u32[0];
		uint64_t data_u64[0];
		struct {
			uint64_t address;
			uint64_t size;
		} ref;
		struct kdbus_creds creds;
		struct kdbus_manager_msg_name_change name_change;
	};
};

enum {
	KDBUS_MSG_FLAGS_EXPECT_REPLY = 1,
	KDBUS_MSG_FLAGS_NO_AUTO_START = 2, /* possibly? */
};

enum {
	KDBUS_PAYLOAD_DBUS1,
	KDBUS_PAYLOAD_GVARIANT,
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
 * ts_nsec: timestamp when message was sent to the kernel
 */
struct kdbus_msg {
	uint64_t size;
	uint64_t flags;
	uint64_t dst_id;	/* 0: well known name in data, ~0: multicast, otherwise: unique name */
	uint64_t src_id;	/* 0: from kernel, otherwise: unique name */
	uint64_t cookie;	/* userspace-supplied cookie */
	uint64_t cookie_reply;	/* cookie of msg this is a reply to. non-zero for replies, 0 for requests. */
	uint64_t payload_type;	/* 'DBUSDBUS', 'GVARIANT', ... */
	struct kdbus_msg_data data[0];
};

enum {
	KDBUS_POLICY_NAME,
	KDBUS_POLICY_ACCESS,
};

enum {
	KDBUS_POLICY_USER,
	KDBUS_POLICY_GROUP,
	KDBUS_POLICY_WORLD,
};

enum {
	KDBUS_POLICY_RECV = 4,
	KDBUS_POLICY_SEND = 2,
	KDBUS_POLICY_OWN = 1,
};

struct kdbus_policy {
	uint64_t size;
	uint64_t type; /* NAME or ACCESS */
	union {
		char name[0];
		struct {
			uint32_t type;  /* USER, GROUP, WORLD */
			uint32_t bits;  /* RECV, SEND, OWN */
			uint64_t id;    /* uid, gid, 0 */
		} access;
	};
};

struct kdbus_cmd_policy {
	uint64_t size;
	uint8_t buffer[0];	/* a series of KDBUS_POLICY_NAME plus one or more KDBUS_POLICY_ACCESS each. */
};

struct kdbus_cmd_hello {
	/* userspace → kernel, kernel → userspace */
	uint64_t kernel_flags;	/* userspace specifies its
				 * capabilities, kernel returns its
				 * capabilites. Kernel might refuse
				 * client's capabilities by returning
				 * an error from KDBUS_CMD_HELLO */

	/* userspace → kernel */
	uint64_t pid;		/* To allow translator services which
				 * connect to the bus on behalf of
				 * somebody else, allow specifiying
				 * the PID of the client to connect on
				 * behalf on. Normal clients should
				 * pass this as 0 (i.e. to do things
				 * under their own PID). Priviliged
				 * clients can pass != 0, to operate
				 * on behalf of somebody else. */

	/* kernel → userspace */
	uint64_t bus_flags;	/* this is copied verbatim from the
				 * original KDBUS_CMD_BUS_MAKE
				 * ioctl. It's intended to be useful
				 * to do negotiation of features of
				 * the payload that is transferred. */
	uint64_t id;		/* peer id */
};

struct kdbus_cmd_fname {
	/* userspace → kernel, kernel → userspace */
	uint64_t kernel_flags;	/* When creating a bus/ns/ep feature
				 * kernel negotiation done the same
				 * way as for KDBUS_CMD_BUS_MAKE. */
	/* userspace → kernel */
	uint64_t bus_flags;	/* When a bus is created this value is
				 * copied verbatim into the bus
				 * structure and returned from
				 * KDBUS_CMD_HELLO, later */
	mode_t mode;
	char name[64];
};

enum {
	/* userspace → kernel */
	KDBUS_CMD_NAME_REPLACE_EXISTING = 1,
	KDBUS_CMD_NAME_QUEUE = 2,
	KDBUS_CMD_NAME_ALLOW_REPLACEMENT = 4,
	KDBUS_CMD_NAME_STARTER = 8,

	/* kernel → userspace */
	KDBUS_CMD_NAME_IN_QUEUE = 256,
};

struct kdbus_cmd_name {
	uint64_t flags;
	uint64_t id;		/* We allow registration/deregestration of names of other peers */
	char name[KDBUS_WELL_KNOWN_NAME_LENGTH];
};

struct kdbus_cmd_names {
	uint64_t count;
	struct kdbus_cmd_name names[0];
};

enum {
	KDBUS_CMD_NAME_INFO_ITEM_SECLABEL,
	KDBUS_CMD_NAME_INFO_ITEM_AUDIT,
};

struct kdbus_cmd_name_info_item {
	uint64_t size;
	uint64_t type;
	uint8_t data[0];
};

struct kdbus_cmd_name_info {
	uint64_t size;
	uint64_t flags;
	uint64_t id;	/* either fill in a valid ID here or set this to 0, and fill in .name instead */
	char name[KDBUS_WELL_KNOWN_NAME_LENGTH];
	struct kdbus_creds creds;
	struct kdbus_cmd_name_info_item items[0];
};

enum {
	KDBUS_CMD_MATCH_BLOOM,		/* Matches a mask blob against KDBUS_MSG_BLOOM */
	KDBUS_CMD_MATCH_SRC_NAME,	/* Matches a name string against KDBUS_MSG_SRC_NAMES */
	KDBUS_CMD_MATCH_NAME_CHANGE,	/* Matches a name string against KDBUS_MSG_NAME_CHANGE */
	KDBUS_CMD_MATCH_ID_NEW,		/* Matches a uint64_t against KDBUS_MSG_ID_NEW */
	KDBUS_CMD_MATCH_ID_REMOVE,	/* Matches a uint64_t against KDBUS_MSG_ID_REMOVE */
};

struct kdbus_cmd_match_item {
	uint64_t type;
	char data[0];
};

struct kdbus_cmd_match {
	uint64_t size;
	uint64_t id;		/* We allow registration/deregestration of matches for other peers */
	uint64_t cookie;	/* userspace supplied cookie; when removing; kernel deletes everything with same cookie */
	uint64_t src_id;	/* ~0: any. other: exact unique match */
	struct kdbus_cmd_match_item items[0];
};

struct kdbus_cmd_monitor {
	uint64_t id;		/* We allow setting the monitor flag of other peers */
	int enabled;		/* A boolean to enable/disable monitoring */
};

/* FD states:
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
	KDBUS_CMD_MSG_SEND =		_IOWR(KDBUS_IOC_MAGIC, 0x40, struct kdbus_msg),
	KDBUS_CMD_MSG_RECV =		_IOWR(KDBUS_IOC_MAGIC, 0x41, struct kdbus_msg),

	KDBUS_CMD_NAME_ACQUIRE =	_IOWR(KDBUS_IOC_MAGIC, 0x50, struct kdbus_cmd_name),
	KDBUS_CMD_NAME_RELEASE =	_IOWR(KDBUS_IOC_MAGIC, 0x51, struct kdbus_cmd_name),
	KDBUS_CMD_NAME_LIST =		_IOWR(KDBUS_IOC_MAGIC, 0x52, struct kdbus_cmd_names),
	KDBUS_CMD_NAME_QUERY =		_IOWR(KDBUS_IOC_MAGIC, 0x53, struct kdbus_cmd_name_info),

	KDBUS_CMD_MATCH_ADD =		_IOWR(KDBUS_IOC_MAGIC, 0x60, struct kdbus_cmd_match),
	KDBUS_CMD_MATCH_REMOVE =	_IOWR(KDBUS_IOC_MAGIC, 0x61, struct kdbus_cmd_match),
	KDBUS_CMD_MONITOR =		_IOWR(KDBUS_IOC_MAGIC, 0x62, struct kdbus_cmd_monitor),

	/* kdbus ep node commands: require ep owner state */
	KDBUS_CMD_EP_POLICY_SET =	_IOWR(KDBUS_IOC_MAGIC, 0x70, struct kdbus_cmd_policy),
};

#endif
