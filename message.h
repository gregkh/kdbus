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

/* array of passed-in file descriptors */
struct kdbus_fds {
	int count;
	struct kdbus_msg_item *items;
	struct file *fp[0];
};

/* array of passed-in payload references */
struct kdbus_payload {
	int count;
	struct kdbus_msg_item *items[0];
};

struct kdbus_meta {
	size_t size;
	size_t allocated_size;
	struct kdbus_msg_item items[0];
};

struct kdbus_kmsg {
	struct kref kref;
	u64 deadline_ns;
	union {
		struct kdbus_fds *fds;
		u64 notification_type; /* short-hand for faster match db lookup. */
	};
	struct kdbus_payload *payloads;
	struct kdbus_meta *meta;
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
const struct kdbus_msg_item *kdbus_msg_get_item(const struct kdbus_msg *msg, u64 type, int index);
void kdbus_kmsg_unref(struct kdbus_kmsg *kmsg);
int kdbus_kmsg_send(struct kdbus_ep *ep,
		    struct kdbus_conn *conn_src,
		    struct kdbus_kmsg *kmsg);
int kdbus_kmsg_recv(struct kdbus_conn *conn, void __user *buf);
#endif
