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

#ifndef __KDBUS_BUS_H
#define __KDBUS_BUS_H

#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/rwsem.h>

#include "policy.h"
#include "util.h"

/**
 * struct kdbus_bus - bus in a domain
 * @kref:		Reference count
 * @disconnected:	Invalidated data
 * @uid_owner:		The uid of the owner of the bus
 * @domain:		Domain of this bus
 * @name:		The bus name
 * @id:			ID of this bus in the domain
 * @lock:		Bus data lock
 * @ep:			Default "bus" endpoint
 * @ep_seq_last:	Last used endpoint id sequence number
 * @conn_seq_last:	Last used connection id sequence number
 * @ep_list:		Endpoints on this bus
 * @bus_flags:		Simple pass-through flags from userspace to userspace
 * @attach_flags_req:	Attach flags required by connecting peers
 * @name_registry:	Name registry of this bus
 * @domain_entry:	Entry in domain
 * @bloom:		Bloom parameters
 * @id128:		Unique random 128 bit ID of this bus
 * @user:		Owner of the bus
 * @policy_db:		Policy database for this bus
 * @notify_list:	List of pending kernel-generated messages
 * @notify_lock:	Notification list lock
 * @notify_flush_lock:	Notification flushing lock
 * @conn_rwlock:	Read/Write lock for all lists of child connections
 * @conn_hash:		Map of connection IDs
 * @monitors_list:	Connections that monitor this bus
 * @meta:		Meta information about the bus creator
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
	struct kdbus_domain *domain;
	const char *name;
	u64 id;
	struct mutex lock;
	struct kdbus_ep *ep;
	atomic64_t ep_seq_last;
	atomic64_t conn_seq_last;
	struct list_head ep_list;
	u64 bus_flags;
	u64 attach_flags_req;
	struct kdbus_name_registry *name_registry;
	struct list_head domain_entry;
	struct kdbus_bloom_parameter bloom;
	u8 id128[16];
	struct kdbus_domain_user *user;
	struct kdbus_policy_db policy_db;
	struct list_head notify_list;
	spinlock_t notify_lock;
	struct mutex notify_flush_lock;

	struct rw_semaphore conn_rwlock;
	DECLARE_HASHTABLE(conn_hash, 8);
	struct list_head monitors_list;

	struct kdbus_meta *meta;
};

struct kdbus_bus *kdbus_bus_new(struct kdbus_domain *domain,
				const struct kdbus_cmd_make *make,
				umode_t mode, kuid_t uid, kgid_t gid);
int kdbus_cmd_bus_creator_info(struct kdbus_conn *conn,
			       struct kdbus_cmd_info *cmd_info);
struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus);
struct kdbus_bus *kdbus_bus_unref(struct kdbus_bus *bus);
void kdbus_bus_disconnect(struct kdbus_bus *bus);

struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id);

#endif
