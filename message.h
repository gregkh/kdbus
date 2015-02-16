/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_MESSAGE_H
#define __KDBUS_MESSAGE_H

#include "util.h"
#include "metadata.h"

/**
 * enum kdbus_msg_data_type - Type of kdbus_msg_data payloads
 * @KDBUS_MSG_DATA_VEC:		Data vector provided by user-space
 * @KDBUS_MSG_DATA_MEMFD:	Memfd payload
 */
enum kdbus_msg_data_type {
	KDBUS_MSG_DATA_VEC,
	KDBUS_MSG_DATA_MEMFD,
};

/**
 * struct kdbus_msg_data - Data payload as stored by messages
 * @type:	Type of payload (KDBUS_MSG_DATA_*)
 * @size:	Size of the described payload
 * @off:	The offset, relative to the vec slice
 * @start:	Offset inside the memfd
 * @file:	Backing file referenced by the memfd
 */
struct kdbus_msg_data {
	unsigned int type;
	u64 size;

	union {
		struct {
			u64 off;
		} vec;
		struct {
			u64 start;
			struct file *file;
		} memfd;
	};
};

/**
 * struct kdbus_kmsg_resources - resources of a message
 * @kref:		Reference counter
 * @dst_name:		Short-cut to msg for faster lookup
 * @fds:		Array of file descriptors to pass
 * @fds_count:		Number of file descriptors to pass
 * @data:		Array of data payloads
 * @vec_count:		Number of VEC entries
 * @memfd_count:	Number of MEMFD entries in @data
 * @data_count:		Sum of @vec_count + @memfd_count
 */
struct kdbus_msg_resources {
	struct kref kref;
	const char *dst_name;

	struct file **fds;
	unsigned int fds_count;

	struct kdbus_msg_data *data;
	size_t vec_count;
	size_t memfd_count;
	size_t data_count;
};

struct kdbus_msg_resources *
kdbus_msg_resources_ref(struct kdbus_msg_resources *r);
struct kdbus_msg_resources *
kdbus_msg_resources_unref(struct kdbus_msg_resources *r);

/**
 * struct kdbus_kmsg - internal message handling data
 * @seq:		Domain-global message sequence number
 * @notify_type:	Short-cut for faster lookup
 * @notify_old_id:	Short-cut for faster lookup
 * @notify_new_id:	Short-cut for faster lookup
 * @notify_name:	Short-cut for faster lookup
 * @dst_name_id:	Short-cut to msg for faster lookup
 * @bloom_filter:	Bloom filter to match message properties
 * @bloom_generation:	Generation of bloom element set
 * @notify_entry:	List of kernel-generated notifications
 * @iov:		Array of iovec, describing the payload to copy
 * @iov_count:		Number of array members in @iov
 * @pool_size:		Overall size of inlined data referenced by @iov
 * @proc_meta:		Appended SCM-like metadata of the sending process
 * @conn_meta:		Appended SCM-like metadata of the sending connection
 * @res:		Message resources
 * @msg:		Message from or to userspace
 */
struct kdbus_kmsg {
	u64 seq;
	u64 notify_type;
	u64 notify_old_id;
	u64 notify_new_id;
	const char *notify_name;

	u64 dst_name_id;
	const struct kdbus_bloom_filter *bloom_filter;
	u64 bloom_generation;
	struct list_head notify_entry;

	struct iovec *iov;
	size_t iov_count;
	u64 pool_size;

	struct kdbus_meta_proc *proc_meta;
	struct kdbus_meta_conn *conn_meta;
	struct kdbus_msg_resources *res;

	/* variable size, must be the last member */
	struct kdbus_msg msg;
};

struct kdbus_bus;
struct kdbus_conn;

struct kdbus_kmsg *kdbus_kmsg_new(struct kdbus_bus *bus, size_t extra_size);
struct kdbus_kmsg *kdbus_kmsg_new_from_cmd(struct kdbus_conn *conn,
					   struct kdbus_cmd_send *cmd_send);
void kdbus_kmsg_free(struct kdbus_kmsg *kmsg);

#endif
