/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_MESSAGE_H
#define __KDBUS_MESSAGE_H

#include "internal.h"
#include "metadata.h"

/**
 * struct kdbus_kmsg - internal message handling data
 * @notification_type	short-cut for faster lookup
 * @dst_name		short-cut to msg for faster lookup
 * @bloom		short-cut to msg for faster lookup
 * @bloom_size		short-cut to msg for faster lookup
 * @fds			array of file descriptors to pass
 * @fds_count		number of file descriptors to pass
 * @meta		appended SCM-like metadata of the sending process
 * @vecs_size		size of PAYLOAD data
 * @vecs_count		number of PAYLOAD vectors
 * @memfds_count	number of memfds to pass
 * @msg			message from userspace
 */
struct kdbus_kmsg {
	u64 notification_type;
	const char *dst_name;
	const u64 *bloom;
	unsigned int bloom_size;
	const int *fds;
	unsigned int fds_count;

	struct kdbus_meta meta;

	size_t vecs_size;
	unsigned int vecs_count;
	unsigned int memfds_count;

	struct kdbus_msg msg;
};

struct kdbus_ep;
struct kdbus_conn;

int kdbus_kmsg_new(size_t extra_size, struct kdbus_kmsg **m);
int kdbus_kmsg_new_from_user(struct kdbus_conn *conn, struct kdbus_msg __user *msg, struct kdbus_kmsg **m);
void kdbus_kmsg_free(struct kdbus_kmsg *kmsg);
#endif
