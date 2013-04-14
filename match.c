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
	u64 type;
	union {
		char	*name;
		char	*bloom;
		u64	id;
	};

	struct list_head	list_entry;
};

struct kdbus_match_db_entry {
	u64			id;
	u64			cookie;
	u64			src_id;
	struct list_head	list_entry;
	struct list_head	items_list;
};

static void
kdbus_match_db_entry_item_free(struct kdbus_match_db_entry_item *item)
{
	switch (item->type) {
	case KDBUS_CMD_MATCH_BLOOM:
		kfree(item->bloom);
		break;
	case KDBUS_CMD_MATCH_SRC_NAME:
	case KDBUS_CMD_MATCH_NAME_ADD:
	case KDBUS_CMD_MATCH_NAME_REMOVE:
	case KDBUS_CMD_MATCH_NAME_CHANGE:
		kfree(item->name);
		break;
	case KDBUS_CMD_MATCH_ID_ADD:
	case KDBUS_CMD_MATCH_ID_REMOVE:
	case KDBUS_CMD_MATCH_ID_CHANGE:
		break;
	}

	list_del(&item->list_entry);
	kfree(item);
}

static void kdbus_match_db_entry_free(struct kdbus_match_db_entry *e)
{
	struct kdbus_match_db_entry_item *ei, *ei_tmp;

	list_for_each_entry_safe(ei, ei_tmp, &e->items_list, list_entry)
		kdbus_match_db_entry_item_free(ei);

	list_del(&e->list_entry);
	kfree(e);
}

static void __kdbus_match_db_free(struct kref *kref)
{
	struct kdbus_match_db_entry *e, *tmp;
	struct kdbus_match_db *db =
		container_of(kref, struct kdbus_match_db, kref);

	mutex_lock(&db->entries_lock);
	list_for_each_entry_safe(e, tmp, &db->entries, list_entry)
		kdbus_match_db_entry_free(e);
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

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_match))
		return ERR_PTR(-EFAULT);

	if (size < sizeof(*cmd_match) || size > 0xffff)
		return ERR_PTR(-EMSGSIZE);

	return memdup_user(buf, size);
}

int kdbus_cmd_match_db_add(struct kdbus_match_db *db,
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
	INIT_LIST_HEAD(&e->items_list);
	e->id = cmd_match->id;
	e->src_id = cmd_match->src_id;
	e->cookie = cmd_match->cookie;
	list_add_tail(&e->list_entry, &db->entries);

	while (size > 0) {
		struct kdbus_match_db_entry_item *ei;

		ei = kzalloc(sizeof(*ei), GFP_KERNEL);
		if (!ei) {
			ret = -ENOMEM;
			goto exit_unlock;
		}

		ei->type = item->type;
		INIT_LIST_HEAD(&ei->list_entry);

		switch (item->type) {
		case KDBUS_CMD_MATCH_BLOOM:
			ei->bloom =
				kmemdup(item->data,
					item->size - offsetof(struct kdbus_cmd_match_item, data),
					GFP_KERNEL);
			break;
		case KDBUS_CMD_MATCH_SRC_NAME:
		case KDBUS_CMD_MATCH_NAME_ADD:
		case KDBUS_CMD_MATCH_NAME_REMOVE:
		case KDBUS_CMD_MATCH_NAME_CHANGE:
			ei->name = kstrdup(item->data, GFP_KERNEL);
			break;
		case KDBUS_CMD_MATCH_ID_ADD:
		case KDBUS_CMD_MATCH_ID_REMOVE:
		case KDBUS_CMD_MATCH_ID_CHANGE:
			ei->id = *(u64 *) item->data;
			break;
		}

		list_add_tail(&ei->list_entry, &e->items_list);

		size -= item->size;
		item = (struct kdbus_cmd_match_item *)
			((u8 *) item + item->size);
	}

exit_unlock:
	mutex_unlock(&db->entries_lock);
	kfree(cmd_match);

	return ret;
}

int kdbus_cmd_match_db_remove(struct kdbus_match_db *db,
			      void __user *buf)
{
	struct kdbus_cmd_match *cmd_match = cmd_match_from_user(buf);
	struct kdbus_match_db_entry *e, *tmp;

	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	mutex_lock(&db->entries_lock);
	list_for_each_entry_safe(e, tmp, &db->entries, list_entry)
		if (e->cookie == cmd_match->cookie &&
		    e->id == cmd_match->id)
			kdbus_match_db_entry_free(e);
	mutex_unlock(&db->entries_lock);

	kfree(cmd_match);

	return 0;
}
