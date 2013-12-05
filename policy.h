/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_POLICY_H
#define __KDBUS_POLICY_H

#include <linux/hashtable.h>

#include "internal.h"

struct kdbus_policy_db {
	struct kref	kref;
	DECLARE_HASHTABLE(entries_hash, 6);
	DECLARE_HASHTABLE(send_access_hash, 6);
	struct list_head timeout_list;
	struct mutex	entries_lock;
	struct mutex	cache_lock;

	struct work_struct work;
	struct timer_list timer;
};

struct kdbus_conn;

int kdbus_policy_db_new(struct kdbus_policy_db **db);
void kdbus_policy_db_unref(struct kdbus_policy_db *db);
int kdbus_cmd_policy_set_from_user(struct kdbus_policy_db *db,
				   void __user *buf);
int kdbus_policy_db_check_send_access(struct kdbus_policy_db *db,
				      struct kdbus_conn *conn_src,
				      struct kdbus_conn *conn_dst,
				      u64 reply_deadline_ns);
int kdbus_policy_db_check_own_access(struct kdbus_policy_db *db,
				     struct kdbus_conn *conn,
				     const char *name);
void kdbus_policy_db_remove_conn(struct kdbus_policy_db *db,
				 struct kdbus_conn *conn);
#endif
