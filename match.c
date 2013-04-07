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

struct kdbus_match_db_entry_item {

	struct list_head	list;
};

struct kdbus_match_db_entry {
	u64			id;
	u64			cookie;
	u64			src_id;
	struct list_head	list_entry;
};

static void __kdbus_match_db_free(struct kref *kref)
{
	struct kdbus_match_db_entry *e, *tmp;
	struct kdbus_match_db *db =
		container_of(kref, struct kdbus_match_db, kref);

	mutex_lock(&db->entries_lock);
	list_for_each_entry_safe(e, tmp, &db->entries, list_entry) {
		list_del(&e->list_entry);
		kfree(e);
	}
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
	mutex_init(&db->entries_lock);
	INIT_LIST_HEAD(&db->entries);

	return db;
}

static
struct kdbus_cmd_match *cmd_match_from_user(void __user *buf)
{
	struct kdbus_cmd_match *cmd_match;
	u64 size;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_match, size))
		return ERR_PTR(-EFAULT);

	if (size < sizeof(*cmd_match) || size > 0xffff)
		return ERR_PTR(-EMSGSIZE);

	return memdup_user(buf, size);
}

int kdbus_match_db_add(struct kdbus_match_db *db,
		       void __user *buf)
{
	struct kdbus_cmd_match *cmd_match = cmd_match_from_user(buf);
	struct kdbus_cmd_match_item *item;
	struct kdbus_match_db_entry *e;
	u64 size;
	int ret = 0;

	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	size = cmd_match->size;
	item = cmd_match->items;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	mutex_lock(&db->entries_lock);
	INIT_LIST_HEAD(&e->list_entry);
	e->id = cmd_match->id;
	e->src_id = cmd_match->src_id;
	e->cookie = cmd_match->cookie;
	list_add_tail(&e->list_entry, &db->entries);

	while (size > 0) {
		// ...
		size -= item->size;
		item = (struct kdbus_cmd_match_item *) ((u8 *) item + item->size);
	}

	mutex_unlock(&db->entries_lock);
	kfree(cmd_match);

	return ret;
}

int kdbus_match_db_remove(struct kdbus_match_db *db,
			  void __user *buf)
{
	struct kdbus_cmd_match *cmd_match = cmd_match_from_user(buf);

	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	// ...

	kfree(cmd_match);

	return 0;
}
