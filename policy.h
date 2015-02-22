/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_POLICY_H
#define __KDBUS_POLICY_H

#include <linux/hashtable.h>
#include <linux/rwsem.h>

struct kdbus_conn;
struct kdbus_item;

/**
 * struct kdbus_policy_db - policy database
 * @entries_hash:	Hashtable of entries
 * @entries_rwlock:	Mutex to protect the database's access entries
 */
struct kdbus_policy_db {
	DECLARE_HASHTABLE(entries_hash, 6);
	struct rw_semaphore entries_rwlock;
};

void kdbus_policy_db_init(struct kdbus_policy_db *db);
void kdbus_policy_db_clear(struct kdbus_policy_db *db);

int kdbus_policy_query_unlocked(struct kdbus_policy_db *db,
				const struct cred *cred, const char *name,
				unsigned int hash);
int kdbus_policy_query(struct kdbus_policy_db *db, const struct cred *cred,
		       const char *name, unsigned int hash);

void kdbus_policy_remove_owner(struct kdbus_policy_db *db,
			       const void *owner);
int kdbus_policy_set(struct kdbus_policy_db *db,
		     const struct kdbus_item *items,
		     size_t items_size,
		     size_t max_policies,
		     bool allow_wildcards,
		     const void *owner);

#endif
