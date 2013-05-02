/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
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

struct kdbus_kmsg {
	struct kref kref;
	u64 deadline_ns;

	/* short-hand for faster match db lookup. */
	u64 notification_type;

	/* appended SCM-like metadata */
	struct kdbus_item *meta;
	size_t meta_size;
	size_t meta_allocated_size;

	/* inlined PAYLOAD_VECs */
	struct kdbus_item *vecs;
	size_t vecs_size;

	/* passed file descriptors */
	struct kdbus_item *fds;
	struct file **fds_fp;
	unsigned int fds_count;

	struct kdbus_conn *conn_src;
	struct kdbus_msg msg;
};

struct kdbus_msg_list_entry {
	struct kdbus_kmsg *kmsg;
	struct list_head entry;
};

struct kdbus_ep;
struct kdbus_conn;

int kdbus_kmsg_new(size_t extra_size, struct kdbus_kmsg **m);
int kdbus_kmsg_new_from_user(struct kdbus_conn *conn, void __user *argp, struct kdbus_kmsg **m);
const struct kdbus_item *kdbus_msg_get_item(const struct kdbus_msg *msg, u64 type, unsigned int index);
void kdbus_kmsg_unref(struct kdbus_kmsg *kmsg);
int kdbus_kmsg_send(struct kdbus_ep *ep,
		    struct kdbus_conn *conn_src,
		    struct kdbus_kmsg *kmsg);
int kdbus_kmsg_recv(struct kdbus_conn *conn, void __user *buf);
#endif
