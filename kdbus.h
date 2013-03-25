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
 * id: message sequence number
 * src_id: who sent the message
 * src_uid: uid of sending process
 * src_gid: gid of sending process
 * src_pid: pid of sending process
 * src_tid: tid of sending process
 * ts_nsec: timestamp when message was sent to the kernel
 */
struct kdbus_msg {
	__u64 dst_id;
	__u64 filter;

	__u64 id;
	__u64 src_id;
	__kernel_uid_t src_uid;
	__kernel_gid_t src_gid;
	__kernel_pid_t src_pid;
	__kernel_pid_t src_tid;
	__u64 capabilities[2];
	__u64 ts_nsec;
	__u64 flags;
	__u64 data_size;
};

enum kdbus_cmd {
	/* kdbus control commands */
	KDBUS_CMD_BUS_CREATE =    _IOW(KDBUS_IOC_MAGIC, 0x00, struct kdbus_cmd_name),
	KDBUS_CMD_NS_CREATE =     _IOW(KDBUS_IOC_MAGIC, 0x10, struct kdbus_cmd_name),

	/* kdbus endpoint commands */
	KDBUS_CMD_EP_CREATE =     _IOWR(KDBUS_IOC_MAGIC, 0x30, struct kdbus_cmd_name),
	KDBUS_CMD_EP_REMOVE =     _IOWR(KDBUS_IOC_MAGIC, 0x31, struct kdbus_cmd_name),
	KDBUS_CMD_EP_POLICY_SET = _IOWR(KDBUS_IOC_MAGIC, 0x32, int),

	KDBUS_CMD_NAME_ACQUIRE =  _IOWR(KDBUS_IOC_MAGIC, 0x50, int),
	KDBUS_CMD_NAME_RELEASE =  _IOWR(KDBUS_IOC_MAGIC, 0x51, int),
	KDBUS_CMD_NAME_LIST =     _IOWR(KDBUS_IOC_MAGIC, 0x52, int),

	KDBUS_CMD_MATCH_ADD =     _IOWR(KDBUS_IOC_MAGIC, 0x60, int),
	KDBUS_CMD_MATCH_REMOVE =  _IOWR(KDBUS_IOC_MAGIC, 0x61, int),

	KDBUS_CMD_MSG_SEND =      _IOWR(KDBUS_IOC_MAGIC, 0x80, struct kdbus_msg),
	KDBUS_CMD_MSG_RECV =      _IOWR(KDBUS_IOC_MAGIC, 0x81, struct kdbus_msg),
};

#endif
