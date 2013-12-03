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

#ifndef __KDBUS_MATCH_H
#define __KDBUS_MATCH_H

#include "internal.h"

struct kdbus_match_db {
	struct kref		kref;
	struct list_head	entries;
	struct mutex		entries_lock;
};

struct kdbus_conn;
struct kdbus_kmsg;

int kdbus_match_db_new(struct kdbus_match_db **db);
struct kdbus_match_db *kdbus_match_db_ref(struct kdbus_match_db *db);
void kdbus_match_db_unref(struct kdbus_match_db *db);
int kdbus_match_db_add(struct kdbus_conn *conn, void __user *buf);
int kdbus_match_db_remove(struct kdbus_conn *conn, void __user *buf);
bool kdbus_match_db_match_kmsg(struct kdbus_match_db *db,
			       struct kdbus_conn *conn_src,
			       struct kdbus_kmsg *kmsg);
#endif
