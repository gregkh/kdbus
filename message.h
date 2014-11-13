/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
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
 * struct kdbus_kmsg - internal message handling data
 * @seq:		Domain-global message sequence number
 * @notify_type:	Short-cut for faster lookup
 * @notify_old_id:	Short-cut for faster lookup
 * @notify_new_id:	Short-cut for faster lookup
 * @notify_name:	Short-cut for faster lookup
 * @dst_name:		Short-cut to msg for faster lookup
 * @dst_name_id:	Short-cut to msg for faster lookup
 * @bloom_filter:	Bloom filter to match message properties
 * @bloom_generation:	Generation of bloom element set
 * @fds:		Array of file descriptors to pass
 * @fds_count:		Number of file descriptors to pass
 * @meta:		Appended SCM-like metadata of the sending process
 * @vecs_size:		Size of PAYLOAD data
 * @vecs_count:		Number of PAYLOAD vectors
 * @memfds_count:	Number of memfds to pass
 * @notify_entry:	List of kernel-generated notifications
 * @msg:		Message from or to userspace
 */
struct kdbus_kmsg {
	u64 seq;
	u64 notify_type;
	u64 notify_old_id;
	u64 notify_new_id;
	const char *notify_name;

	const char *dst_name;
	u64 dst_name_id;
	const struct kdbus_bloom_filter *bloom_filter;
	u64 bloom_generation;
	struct file **fds;
	unsigned int fds_count;
	struct kdbus_meta *meta;
	size_t vecs_size;
	unsigned int vecs_count;
	struct file **memfds;
	unsigned int memfds_count;
	struct list_head notify_entry;

	/* variable size, must be the last member */
	struct kdbus_msg msg;
};

struct kdbus_ep;
struct kdbus_conn;

struct kdbus_kmsg *kdbus_kmsg_new(size_t extra_size);
struct kdbus_kmsg *kdbus_kmsg_new_from_user(struct kdbus_conn *conn,
					    struct kdbus_msg __user *msg);
void kdbus_kmsg_free(struct kdbus_kmsg *kmsg);

int kdbus_kmsg_attach_metadata(struct kdbus_kmsg *kmsg,
			       struct kdbus_conn *conn_src,
			       struct kdbus_conn *conn_dst);
#endif
