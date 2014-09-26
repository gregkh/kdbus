/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
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
#include <linux/idr.h>
#include <linux/kref.h>

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
 * @conn_idr:		Map of connection device minor nummbers
 * @conn_hash:		Map of connection IDs
 * @ep_list:		Endpoints on this bus
 * @bus_flags:		Simple pass-through flags from userspace to userspace
 * @name_registry:	Domain's list of buses
 * @domain_entry:	Domain's list of buses
 * @monitors_list:	Connections that monitor this bus
 * @bloom:		Bloom parameters
 * @id128:		Unique random 128 bit ID of this bus
 * @user:		Owner of the connection
 * @policy_db:		Policy database for this bus
 * @notify_list:	List of pending kernel-generated messages
 * @notify_lock:	Notification list lock
 * @notify_flush_lock:	Notification flushing lock
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
	u64 ep_seq_last;
	atomic64_t conn_seq_last;
	struct idr conn_idr;
	DECLARE_HASHTABLE(conn_hash, 8);
	struct list_head ep_list;
	u64 bus_flags;
	struct kdbus_name_registry *name_registry;
	struct list_head domain_entry;
	struct list_head monitors_list;
	struct kdbus_bloom_parameter bloom;
	u8 id128[16];
	struct kdbus_domain_user *user;
	struct kdbus_policy_db policy_db;
	struct list_head notify_list;
	spinlock_t notify_lock;
	struct mutex notify_flush_lock;
};

int kdbus_bus_make_user(const struct kdbus_cmd_make *make,
			char **name, struct kdbus_bloom_parameter *bloom);
int kdbus_bus_new(struct kdbus_domain *domain,
		  const struct kdbus_cmd_make *make,
		  const char *name,
		  const struct kdbus_bloom_parameter *bloom,
		  umode_t mode, kuid_t uid, kgid_t gid,
		  struct kdbus_bus **bus);
struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus);
struct kdbus_bus *kdbus_bus_unref(struct kdbus_bus *bus);
void kdbus_bus_disconnect(struct kdbus_bus *bus);

bool kdbus_bus_cred_is_privileged(const struct kdbus_bus *bus,
				  const struct cred *cred);
bool kdbus_bus_uid_is_privileged(const struct kdbus_bus *bus);
struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id);
#endif
