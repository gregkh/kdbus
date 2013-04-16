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

#define KDBUS_CONN_MAX_MSGS		50
#define KDBUS_CONN_MAX_ALLOCATED_BYTES	SZ_64K

/*
 * kdbus connection
 * - connection to a control node or an endpoint
 */
enum kdbus_conn_type {
	KDBUS_CONN_UNDEFINED,
	KDBUS_CONN_CONTROL,
	KDBUS_CONN_NS_OWNER,
	KDBUS_CONN_BUS_OWNER,
	KDBUS_CONN_EP,
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
	bool active;	/* did the connection say hello yet? */
	bool monitor;

	struct mutex msg_lock;
	struct mutex names_lock;
	struct list_head msg_list;

	struct hlist_node hentry;

	struct list_head connection_entry;
	struct list_head names_list;
	struct list_head names_queue_list;

	struct work_struct work;
	struct timer_list timer;

	struct kdbus_creds creds;
	struct kdbus_match_db *match_db;

	int msg_count;
	int allocated_size;
};

void kdbus_conn_schedule_timeout_scan(struct kdbus_conn *conn);
int kdbus_conn_add_size_allocation(struct kdbus_conn *conn, u64 size);
void kdbus_conn_sub_size_allocation(struct kdbus_conn *conn, u64 size);

#endif
