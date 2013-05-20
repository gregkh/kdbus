/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
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

/*
 * kdbus connection
 * - connection to a control node or an endpoint
 */
enum kdbus_conn_type {
	_KDBUS_CONN_NULL,
	KDBUS_CONN_CONTROL,		/* new fd of a control node */
	KDBUS_CONN_CONTROL_NS_OWNER,	/* fd to hold a namespace */
	KDBUS_CONN_CONTROL_BUS_OWNER,	/* fd to hold a bus */
	KDBUS_CONN_EP,			/* new fd of a bus node */
	KDBUS_CONN_EP_CONNECTED,	/* connection after HELLO */
	KDBUS_CONN_EP_OWNER,		/* fd to hold an endpoint */
};

struct kdbus_conn {
	enum kdbus_conn_type type;
	struct kdbus_ns *ns;
	union {
		struct kdbus_ns *ns_owner;
		struct kdbus_bus *bus_owner;
		struct kdbus_ep *ep;
	};
	u64 id;		/* id of the connection on the bus */
	u64 flags;

	struct mutex lock;
	struct mutex names_lock;
	struct mutex accounting_lock;

	struct list_head msg_list;
	struct hlist_node hentry;
	struct list_head connection_entry;	/* bus' connections */
	struct list_head monitor_entry;		/* bus' monitor connections */
	struct list_head names_list;		/* names on this connection */
	struct list_head names_queue_list;

	struct work_struct work;
	struct timer_list timer;

	struct kdbus_creds creds;
	struct kdbus_match_db *match_db;

#ifdef CONFIG_AUDITSYSCALL
	u64 audit_ids[2];
#endif

#ifdef CONFIG_SECURITY
	char *sec_label;
	u32 sec_label_len;
#endif

	/* reference to the taks owning the connection */
	struct task_struct *task;

	/* connection accounting */
	unsigned int msg_count;
	size_t allocated_size;

	/* userspace-supplied buffer to fill with message data */
	struct kdbus_pool pool;
};

struct kdbus_kmsg;
struct kdbus_conn_queue;

int kdbus_conn_kmsg_send(struct kdbus_ep *ep,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg);
void kdbus_conn_queue_cleanup(struct kdbus_conn_queue *queue);
int kdbus_conn_queue_insert(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg,
			    u64 deadline_ns);

int kdbus_conn_accounting_add_size(struct kdbus_conn *conn, size_t size);
void kdbus_conn_accounting_sub_size(struct kdbus_conn *conn, size_t size);
#endif
