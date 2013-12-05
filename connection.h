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

#ifndef __KDBUS_CONNECTION_H
#define __KDBUS_CONNECTION_H

#include "internal.h"
#include "pool.h"
#include "metadata.h"

struct kdbus_conn {
	struct kref kref;
	bool disconnected;			/* invalidated data */
	struct kdbus_ep *ep;

	u64 id;
	u64 flags;
	u64 attach_flags;

	struct mutex lock;
	struct mutex names_lock;
	struct mutex accounting_lock;

	struct list_head msg_list;
	struct hlist_node hentry;
	struct list_head monitor_entry;		/* bus' monitor connections */

	struct list_head names_list;		/* names on this connection */
	struct list_head names_queue_list;
	size_t names;				/* number of names */

	struct work_struct work;
	struct timer_list timer;

	struct kdbus_match_db *match_db;

	/* connection creator metadata */
	struct kdbus_meta meta;

	/* connection accounting */
	unsigned int msg_count;
	size_t allocated_size;

	/* buffer to fill with message data */
	struct kdbus_pool *pool;
};

struct kdbus_kmsg;
struct kdbus_conn_queue;
struct kdbus_name_registry;

int kdbus_conn_new(struct kdbus_ep *ep,
		   struct kdbus_cmd_hello *hello,
		   struct kdbus_conn **conn);
struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn);
void kdbus_conn_unref(struct kdbus_conn *conn);
void kdbus_conn_disconnect(struct kdbus_conn *conn);

int kdbus_conn_recv_msg(struct kdbus_conn *conn, __u64 __user *buf);
int kdbus_cmd_conn_info(struct kdbus_name_registry *reg,
			struct kdbus_conn *conn,
			void __user *buf);
int kdbus_conn_kmsg_send(struct kdbus_ep *ep,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg);
void kdbus_conn_queue_cleanup(struct kdbus_conn_queue *queue);
int kdbus_conn_queue_insert(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg,
			    u64 deadline_ns);
int kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			     struct kdbus_conn *conn_src);
int kdbus_conn_accounting_add_size(struct kdbus_conn *conn, size_t size);
void kdbus_conn_accounting_sub_size(struct kdbus_conn *conn, size_t size);
#endif
