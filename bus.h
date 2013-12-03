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

/**
 * kdbus_bus - bus instance
 * @kref		reference count
 * @disconnected	invalidated data
 * @uid_owner		the uid of the owner of the bus
 * @ns			namespace of this bus
 * @name		the bus name
 * @id			id of this bus in the namespace
 * @lock		bus data lock
 * @ep_id_next		next endpoint id sequence number
 * @conn_id_next	next connection id sequence number
 * @msg_id_next		next message id sequence number
 * @conn_idr		map of connection ids
 * @conn_hash
 * @eps_list		endpoints on this bus
 * @bus_flags		simple pass-thru flags from userspace to userspace
 * @bloom_size		bloom filter size
 * @name_registry	namespace's list of buses
 * @ns_entry		namespace's list of buses
 * @monitors_list	connections that monitor this bus
 * @id128		unique random 128 bit id of this bus
 *
 * A bus provides a "bus" endpoint / device node.
 *
 * A bus is created by opening the control node and issuing the
 * KDBUS_CMD_BUS_MAKE iotcl. Closing this file immediately destroys
 * the bus.
 */
struct kdbus_bus {
	struct kref kref;
	bool disconnected;
	kuid_t uid_owner;
	struct kdbus_ns *ns;
	const char *name;
	u64 id;
	struct mutex lock;
	u64 ep_id_next;
	u64 conn_id_next;
	u64 msg_id_next;
	struct idr conn_idr;
	DECLARE_HASHTABLE(conn_hash, 6);
	struct list_head eps_list;
	u64 bus_flags;
	size_t bloom_size;
	struct kdbus_name_registry *name_registry;
	struct list_head ns_entry;
	struct list_head monitors_list;
	u8 id128[16];
};

int kdbus_bus_make_user(void __user *buf,
			struct kdbus_cmd_bus_make **make, char **name);
int kdbus_bus_new(struct kdbus_ns *ns,
		  struct kdbus_cmd_bus_make *make, const char *name,
		  umode_t mode, kuid_t uid, kgid_t gid, struct kdbus_bus **bus);
struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus);
void kdbus_bus_unref(struct kdbus_bus *bus);
void kdbus_bus_disconnect(struct kdbus_bus *bus);

bool kdbus_bus_uid_is_privileged(const struct kdbus_bus *bus);
void kdbus_bus_scan_timeout_list(struct kdbus_bus *bus);
struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id);
#endif
