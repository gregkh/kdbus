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

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/hash.h>
#include <linux/uaccess.h>
#include <linux/sizes.h>

#include "match.h"
#include "connection.h"
#include "ep.h"
#include "message.h"
#include "bus.h"

struct kdbus_match_db_entry_item {
	u64 type;
	union {
		char	*name;
		u64	*bloom;
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
	case KDBUS_MATCH_BLOOM:
		kfree(item->bloom);
		break;

	case KDBUS_MATCH_SRC_NAME:
	case KDBUS_MATCH_NAME_ADD:
	case KDBUS_MATCH_NAME_REMOVE:
	case KDBUS_MATCH_NAME_CHANGE:
		kfree(item->name);
		break;

	case KDBUS_MATCH_ID_ADD:
	case KDBUS_MATCH_ID_REMOVE:
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

static inline
bool kdbus_match_db_test_bloom(const u64 *filter,
			       const u64 *mask,
			       size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if ((filter[i] & mask[i]) != mask[i])
			return false;

	return true;
}

static inline
bool kdbus_match_db_test_src_names(const char *haystack,
				   size_t haystack_size,
				   const char *needle)
{
	size_t i;

	for (i = 0; i < haystack_size; i += strlen(haystack) + 1)
		if (strcmp(haystack + i, needle) == 0)
			return true;

	return false;
}

static
bool kdbus_match_db_match_with_src(struct kdbus_match_db *db,
				   struct kdbus_conn *conn_src,
				   struct kdbus_kmsg *kmsg)
{
	struct kdbus_match_db_entry *e;
	bool matched = false;

	mutex_lock(&db->entries_lock);
	list_for_each_entry(e, &db->entries, list_entry) {
		struct kdbus_match_db_entry_item *ei;

		if (e->src_id != KDBUS_MATCH_SRC_ID_ANY &&
		    e->src_id != conn_src->id)
			continue;

		matched = true;

		list_for_each_entry(ei, &e->items_list, list_entry) {
			if (kmsg->bloom) {
				size_t bloom_size =
					conn_src->ep->bus->bloom_size / sizeof(u64);

				if (!kdbus_match_db_test_bloom(ei->bloom,
							       kmsg->bloom,
							       bloom_size)) {
					matched = false;
					break;
				}
			}

			if (kmsg->src_names) {
				if (!kdbus_match_db_test_src_names(kmsg->src_names,
								   kmsg->src_names_len,
								   ei->name)) {
					matched = false;
					break;
				}
			}
		}

		if (matched)
			break;
	}
	mutex_unlock(&db->entries_lock);

	return matched;
}

static
bool kdbus_match_db_match_from_kernel(struct kdbus_match_db *db,
				      struct kdbus_conn *conn_dst,
				      struct kdbus_kmsg *kmsg)
{
	u64 type = kmsg->notification_type;
	struct kdbus_match_db_entry *e;
	bool matched = false;

	mutex_lock(&db->entries_lock);
	list_for_each_entry(e, &db->entries, list_entry) {
		struct kdbus_match_db_entry_item *ei;

		if (e->src_id != KDBUS_MATCH_SRC_ID_ANY &&
		    e->src_id != 0)
			continue;

		matched = true;

		list_for_each_entry(ei, &e->items_list, list_entry) {
			if (ei->type == KDBUS_MATCH_ID_ADD &&
			    type != KDBUS_MSG_ID_ADD) {
				matched = false;
				break;
			}

			if (ei->type == KDBUS_MATCH_ID_REMOVE &&
			    type != KDBUS_MSG_ID_REMOVE) {
				matched = false;
				break;
			}

			if (ei->type == KDBUS_MATCH_NAME_ADD &&
			    type != KDBUS_MSG_NAME_ADD) {
				matched = false;
				break;
			}

			if (ei->type == KDBUS_MATCH_NAME_CHANGE &&
			    type != KDBUS_MSG_NAME_CHANGE) {
				matched = false;
				break;
			}

			if (ei->type == KDBUS_MATCH_NAME_REMOVE &&
			    type != KDBUS_MSG_NAME_REMOVE) {
				matched = false;
				break;
			}
		}

		if (matched)
			break;
	}
	mutex_unlock(&db->entries_lock);

	return matched;
}

bool kdbus_match_db_match_kmsg(struct kdbus_match_db *db,
			       struct kdbus_conn *conn_src,
			       struct kdbus_conn *conn_dst,
			       struct kdbus_kmsg *kmsg)
{
	if (conn_src)
		return kdbus_match_db_match_with_src(db, conn_src, kmsg);
	else
		return kdbus_match_db_match_from_kernel(db, conn_dst, kmsg);
}

static
struct kdbus_cmd_match *cmd_match_from_user(void __user *buf)
{
	struct kdbus_cmd_match *cmd_match;
	u64 size;

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_match))
		return ERR_PTR(-EFAULT);

	if (size < sizeof(*cmd_match) || size > KDBUS_MATCH_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	return memdup_user(buf, size);
}

int kdbus_cmd_match_db_add(struct kdbus_conn *conn, void __user *buf)
{
	struct kdbus_match_db *db = conn->match_db;
	struct kdbus_cmd_match *cmd_match;
	struct kdbus_item *item;
	struct kdbus_match_db_entry *e;
	int ret = 0;

	cmd_match = cmd_match_from_user(buf);
	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	mutex_lock(&db->entries_lock);
	INIT_LIST_HEAD(&e->list_entry);
	INIT_LIST_HEAD(&e->items_list);
	e->id = cmd_match->id;
	e->src_id = cmd_match->src_id;
	e->cookie = cmd_match->cookie;

	KDBUS_ITEM_FOREACH_VALIDATE(item, cmd_match) {
		struct kdbus_match_db_entry_item *ei;
		size_t size;

		if (item->size < sizeof(*item)) {
			ret = -EBADMSG;
			break;
		}

		ei = kzalloc(sizeof(*ei), GFP_KERNEL);
		if (!ei) {
			ret = -ENOMEM;
			break;
		}

		ei->type = item->type;
		INIT_LIST_HEAD(&ei->list_entry);

		switch (item->type) {
		case KDBUS_MATCH_BLOOM:
			size = item->size - offsetof(struct kdbus_item, data);
			if (size != conn->ep->bus->bloom_size) {
				ret = -EBADMSG;
				break;
			}

			ei->bloom = kmemdup(item->data, item->size - offsetof(struct kdbus_item, data),
					GFP_KERNEL);
			break;

		case KDBUS_MATCH_SRC_NAME:
		case KDBUS_MATCH_NAME_ADD:
		case KDBUS_MATCH_NAME_REMOVE:
		case KDBUS_MATCH_NAME_CHANGE:
			ei->name = kstrdup(item->str, GFP_KERNEL);
			if (!ei->name)
				ret = -ENOMEM;
			break;

		case KDBUS_MATCH_ID_ADD:
		case KDBUS_MATCH_ID_REMOVE:
			ei->id = item->id;
			break;
		}

		list_add_tail(&ei->list_entry, &e->items_list);
	}

	if (ret >= 0) {
		list_add_tail(&e->list_entry, &db->entries);
	} else {
		kdbus_match_db_entry_free(e);
		kfree(e);
	}

	mutex_unlock(&db->entries_lock);
	kfree(cmd_match);

	return ret;
}

int kdbus_cmd_match_db_remove(struct kdbus_match_db *db, void __user *buf)
{
	struct kdbus_cmd_match *cmd_match;
	struct kdbus_match_db_entry *e, *tmp;

	cmd_match = cmd_match_from_user(buf);
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
