/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
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
#include <linux/rwsem.h>

#include "node.h"
#include "policy.h"
#include "util.h"

/**
 * struct kdbus_bus - bus in a domain
 * @node:		kdbus_node
 * @id:			ID of this bus in the domain
 * @bus_flags:		Simple pass-through flags from userspace to userspace
 * @attach_flags_req:	KDBUS_ATTACH_* flags required by connecting peers
 * @attach_flags_owner:	KDBUS_ATTACH_* flags of bus creator that other
 *			connections can see or query
 * @id128:		Unique random 128 bit ID of this bus
 * @access:		The access flags for the bus directory
 * @bloom:		Bloom parameters
 * @domain:		Domain of this bus
 * @creator:		Creator of the bus
 * @creator_meta:	Meta information about the bus creator
 * @policy_db:		Policy database for this bus
 * @name_registry:	Name registry of this bus
 * @conn_rwlock:	Read/Write lock for all lists of child connections
 * @conn_hash:		Map of connection IDs
 * @monitors_list:	Connections that monitor this bus
 * @notify_list:	List of pending kernel-generated messages
 * @notify_lock:	Notification list lock
 * @notify_flush_lock:	Notification flushing lock
 */
struct kdbus_bus {
	struct kdbus_node node;

	/* static */
	u64 id;
	u64 bus_flags;
	u64 attach_flags_req;
	u64 attach_flags_owner;
	u8 id128[16];
	unsigned int access;
	struct kdbus_bloom_parameter bloom;
	struct kdbus_domain *domain;
	struct kdbus_domain_user *creator;
	struct kdbus_meta_proc *creator_meta;

	/* protected by own locks */
	struct kdbus_policy_db policy_db;
	struct kdbus_name_registry *name_registry;

	/* protected by conn_rwlock */
	struct rw_semaphore conn_rwlock;
	DECLARE_HASHTABLE(conn_hash, 8);
	struct list_head monitors_list;

	/* protected by notify_lock */
	struct list_head notify_list;
	spinlock_t notify_lock;
	struct mutex notify_flush_lock;
};

struct kdbus_kmsg;

struct kdbus_bus *kdbus_bus_new(struct kdbus_domain *domain,
				const struct kdbus_cmd *make,
				kuid_t uid, kgid_t gid);
struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus);
struct kdbus_bus *kdbus_bus_unref(struct kdbus_bus *bus);

struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id);
void kdbus_bus_broadcast(struct kdbus_bus *bus, struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg);
void kdbus_bus_eavesdrop(struct kdbus_bus *bus, struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg);

struct kdbus_bus *kdbus_cmd_bus_make(struct kdbus_domain *domain,
				     void __user *argp);
int kdbus_cmd_bus_creator_info(struct kdbus_conn *conn, void __user *argp);

#endif
