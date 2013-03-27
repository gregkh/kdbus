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


#define KDBUS_IOC_MAGIC 0x95

/* kdbus control device commands */
struct kdbus_cmd_name {
	uint64_t capabilities;
	char name[256];
	char reserved[256];
};

struct kdbus_fake_message {
	char msg[256]; /* FIXME obviously... */
};


/**
 * struct kdbus_msg_data
 *
 * type:
 * flags:
 * size:
 * data:
 */
struct kdbus_msg_data {
	__u32 type;
	__u32 flags;
	__u64 size;
	__u8 *data;
};

/**
 * struct kdbus_msg
 *
 * set by userspace:
 * dst_id: destination id
 * filter: bloom filter for the kernel to use to filter messages
 * data_count: number of data structures for this message
 * data: data for the message
 *
 * set by kernel:
 * msg_id: message id, to allow userspace to sort messages
 * src_id: who sent the message
 * src_uid: uid of sending process
 * src_gid: gid of sending process
 * src_pid: pid of sending process
 * src_tid: tid of sending process
 * ts_nsec: timestamp when message was sent to the kernel
 *
 */
struct kdbus_msg {
	__u64 dst_id;
	__u64 filter;

	__u64 msg_id;
	__u64 src_id;
	__u64 flags;
	__kernel_uid_t src_uid;
	__kernel_gid_t src_gid;
	__kernel_pid_t src_pid;
	__kernel_pid_t src_tid;
	__u64 ts_nsec;
	__u64 reserved[8];
	__u32 data_count;
	struct kdbus_msg_data *data;
};



#if 0
/* Old-style dbus had the following message type: */
struct old_dbus_header {
	u8 endianness;		/* 'l' for little endian, 'B' for big endian */
	u8 type;		/* message type */
	u8 flags;
	u8 protocol_version;
	u32 message_length
	u32 cookie;
}

#define DBUS_TYPE_INVALID	0
#define DBUS_TYPE_METHOD_CALL	1
#define DBUS_TYPE_METHOD_RETURN	2
#define DBUS_TYPE_ERROR		3
#define DBUS_TYPE_SIGNAL	4

#define DBUS_FLAG_NO_REPLY_EXPECTED	0x01
#define DBUS_FLAG_NO_AUTO_START		0x02

#define DBUS_FIELD_INVALID	0
#define DBUS_FIELD_PATH		1
#define DBUS_FIELD_INTERFACE	2
#define DBUS_FIELD_MEMBER	3
#define DBUS_FIELD_ERROR_NAME	4
#define DBUS_FIELD_REPLY_SERIAL	5
#define DBUS_FIELD_DESTINATION	6
#define DBUS_FIELD_SENDER	7
#define DBUS_FIELD_SIGNATURE	8
#define DBUS_FIELD_UNIX_FDS	9

#endif

enum kdbus_cmd {
	/* kdbus control commands */
	KDBUS_CMD_BUS_CREATE =    _IOW(KDBUS_IOC_MAGIC, 0x00, struct kdbus_cmd_name),
	KDBUS_CMD_BUS_REMOVE =    _IOW(KDBUS_IOC_MAGIC, 0x01, struct kdbus_cmd_name),
	KDBUS_CMD_NS_CREATE =     _IOW(KDBUS_IOC_MAGIC, 0x10, struct kdbus_cmd_name),
	KDBUS_CMD_NS_REMOVE =     _IOW(KDBUS_IOC_MAGIC, 0x11, struct kdbus_cmd_name),

	/* kdbus endpoint commands */
	KDBUS_CMD_EP_CREATE =     _IOWR(KDBUS_IOC_MAGIC, 0x30, struct kdbus_cmd_name),
	KDBUS_CMD_EP_REMOVE =     _IOWR(KDBUS_IOC_MAGIC, 0x31, struct kdbus_cmd_name),
	KDBUS_CMD_EP_POLICY_SET = _IOWR(KDBUS_IOC_MAGIC, 0x32, int),

	KDBUS_CMD_NAME_ACQUIRE =  _IOWR(KDBUS_IOC_MAGIC, 0x50, int),
	KDBUS_CMD_NAME_RELEASE =  _IOWR(KDBUS_IOC_MAGIC, 0x51, int),
	KDBUS_CMD_NAME_LIST =     _IOWR(KDBUS_IOC_MAGIC, 0x52, int),

	KDBUS_CMD_MATCH_ADD =     _IOWR(KDBUS_IOC_MAGIC, 0x60, int),
	KDBUS_CMD_MATCH_REMOVE =  _IOWR(KDBUS_IOC_MAGIC, 0x61, int),

	KDBUS_CMD_MSG_SEND =      _IOWR(KDBUS_IOC_MAGIC, 0x80, struct kdbus_fake_message),
	KDBUS_CMD_MSG_RECV =      _IOWR(KDBUS_IOC_MAGIC, 0x81, struct kdbus_fake_message),
};

#endif
