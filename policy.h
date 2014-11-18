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

#ifndef __KDBUS_POLICY_H
#define __KDBUS_POLICY_H

#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>

struct kdbus_conn;
struct kdbus_item;

/**
 * struct kdbus_policy_db - policy database
 * @entries_hash:	Hashtable of entries
 * @talk_access_hash:	Hashtable of send access elements
 * @entries_lock:	Mutex to protect the database's access entries
 * @cache_lock:		Mutex to protect the database's cache
 */
struct kdbus_policy_db {
	DECLARE_HASHTABLE(entries_hash, 6);
	DECLARE_HASHTABLE(talk_access_hash, 6);
	struct rw_semaphore entries_rwlock;
	struct mutex cache_lock;
};

void kdbus_policy_db_init(struct kdbus_policy_db *db);
void kdbus_policy_db_clear(struct kdbus_policy_db *db);

int kdbus_policy_check_see_access_unlocked(struct kdbus_policy_db *db,
					   const struct cred *cred,
					   const char *name);
int kdbus_policy_check_talk_access(struct kdbus_policy_db *db,
				   struct kdbus_conn *conn_src,
				   struct kdbus_conn *conn_dst);
int kdbus_policy_check_own_access(struct kdbus_policy_db *db,
				  const struct cred *cred,
				  const char *name);
void kdbus_policy_purge_cache(struct kdbus_policy_db *db,
			      const struct kdbus_conn *conn);
void kdbus_policy_remove_owner(struct kdbus_policy_db *db,
			       const void *owner);
int kdbus_policy_set(struct kdbus_policy_db *db,
		     const struct kdbus_item *items,
		     size_t items_size,
		     size_t max_policies,
		     bool allow_wildcards,
		     const void *owner);

#endif
