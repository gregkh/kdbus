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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/uaccess.h>
#include "kdbus.h"

#include "kdbus_internal.h"

static void __kdbus_match_db_free(struct kref *kref)
{
	struct kdbus_match_db *db =
		container_of(kref, struct kdbus_match_db, kref);

	mutex_lock(&db->entries_lock);
	// ...
	mutex_unlock(&db->entries_lock);

	kfree(db);
}

void kdbus_match_db_unref(struct kdbus_match_db *db)
{
	kref_put(&db->kref, __kdbus_match_db_free);
}

struct kdbus_match_db *kdbus_match_db_new(void)
{
	struct kdbus_match_db *db;

	db = kzalloc(sizeof(*db), GFP_KERNEL);
	if (!db)
		return NULL;

	kref_init(&db->kref);
	hash_init(db->entries_hash);
	mutex_init(&db->entries_lock);

	return db;
}

int kdbus_match_db_add(struct kdbus_match_db *db,
		       void __user *buf)
{
	struct kdbus_cmd_match *cmd_match;
	u64 size;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_match, size))
		return -EFAULT;

	cmd_match = memdup_user(buf, size);
	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	// ...

	kfree(cmd_match);

	return 0;
}

int kdbus_match_db_remove(struct kdbus_match_db *db,
			  void __user *buf)
{
	struct kdbus_cmd_match *cmd_match;
	u64 size;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_match, size))
		return -EFAULT;

	cmd_match = memdup_user(buf, size);
	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	// ...

	kfree(cmd_match);

	return 0;
}
