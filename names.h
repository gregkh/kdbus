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

#ifndef __KDBUS_NAMES_H
#define __KDBUS_NAMES_H

#include <linux/hashtable.h>
#include <linux/rwsem.h>

/**
 * struct kdbus_name_registry - names registered for a bus
 * @entries_hash:	Map of entries
 * @lock:		Registry data lock
 * @name_seq_last:	Last used sequence number to assign to a name entry
 */
struct kdbus_name_registry {
	DECLARE_HASHTABLE(entries_hash, 8);
	struct rw_semaphore rwlock;
	u64 name_seq_last;
};

/**
 * struct kdbus_name_entry - well-know name entry
 * @name:		The well-known name
 * @name_id:		Sequence number of name entry to be able to uniquely
 *			identify a name over its registration lifetime
 * @flags:		KDBUS_NAME_* flags
 * @queue_list:		List of queued waiters for the well-known name
 * @conn_entry:		Entry in connection
 * @hentry:		Entry in registry map
 * @conn:		Connection owning the name
 * @activator:		Connection of the activator queuing incoming messages
 */
struct kdbus_name_entry {
	char *name;
	u64 name_id;
	u64 flags;
	struct list_head queue_list;
	struct list_head conn_entry;
	struct hlist_node hentry;
	struct kdbus_conn *conn;
	struct kdbus_conn *activator;
};

struct kdbus_name_registry *kdbus_name_registry_new(void);
void kdbus_name_registry_free(struct kdbus_name_registry *reg);

int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       const char *name, u64 *flags);
int kdbus_cmd_name_acquire(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   struct kdbus_cmd_name *cmd);
int kdbus_cmd_name_release(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   const struct kdbus_cmd_name *cmd);
int kdbus_cmd_name_list(struct kdbus_name_registry *reg,
			struct kdbus_conn *conn,
			struct kdbus_cmd_name_list *cmd);

struct kdbus_name_entry *kdbus_name_lock(struct kdbus_name_registry *reg,
					 const char *name);
struct kdbus_name_entry *kdbus_name_unlock(struct kdbus_name_registry *reg,
					   struct kdbus_name_entry *entry);

void kdbus_name_remove_by_conn(struct kdbus_name_registry *reg,
			       struct kdbus_conn *conn);

bool kdbus_name_is_valid(const char *p, bool allow_wildcard);

#endif
