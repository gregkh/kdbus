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

#ifndef __KDBUS_BUS_H
#define __KDBUS_BUS_H

#include <linux/idr.h>
#include <linux/hashtable.h>

#include "internal.h"

/*
 * kdbus bus
 * - provides a "bus" endpoint
 * - owns additional endpoints
 * - own all bus connections
 * - new buses are created by opening the control node and
 *   issuing KDBUS_BUS_CREATE
 * - closing the connection destroys the created bus
 */
struct kdbus_bus {
	struct kref kref;		/* reference count */
	kuid_t uid_owner;		/* the uid of the owner of the bus */
	bool disconnected;		/* invalidated data */
	struct kdbus_ns *ns;		/* namespace of this bus */
	const char *name;		/* bus name */
	u64 id;				/* id of this bus in the namespace */
	struct mutex lock;		/* bus data lock */
	u64 ep_id_next;			/* next endpoint id sequence number */
	u64 conn_id_next;		/* next connection id sequence number */
	u64 msg_id_next;		/* next message id sequence number */
	struct idr conn_idr;		/* map of connection ids */
	DECLARE_HASHTABLE(conn_hash, 6);
	struct list_head eps_list;	/* endpoints on this bus */
	u64 bus_flags;			/* simple pass-thru flags from userspace to userspace */
	size_t bloom_size;		/* bloom filter size */
	struct kdbus_name_registry *name_registry;
	struct list_head ns_entry;	/* namespace's list of buses */
	struct list_head monitors_list;	/* connections that monitor */
	u8 id128[16];
};

struct kdbus_cmd_bus_kmake {
	const char *name;
	struct kdbus_cmd_bus_make make;
};

bool kdbus_bus_uid_is_privileged(const struct kdbus_bus *bus);
struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus);
void kdbus_bus_unref(struct kdbus_bus *bus);
void kdbus_bus_disconnect(struct kdbus_bus *bus);
int kdbus_bus_new(struct kdbus_ns *ns, struct kdbus_cmd_bus_kmake *kmake,
		  umode_t mode, kuid_t uid, kgid_t gid, struct kdbus_bus **bus);
void kdbus_bus_scan_timeout_list(struct kdbus_bus *bus);
struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id);
int kdbus_bus_make_user(void __user *buf, struct kdbus_cmd_bus_kmake **kmake);
#endif
