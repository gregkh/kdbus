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
#include "endpoint.h"
#include "message.h"
#include "bus.h"

/**
 * struct kdbus_match_db - message filters
 * @kref:		Reference count
 * @entries:		List of matches
 * @entries_lock:	Match data lock
 */
struct kdbus_match_db {
	struct kref		kref;
	struct list_head	entries;
	struct mutex		entries_lock;
};

/**
 * struct kdbus_match_db_entry_item - a match databate entry item
 * @type:		The type of the item (KDBUS_MATCH_*)
 * @name:		The name tp match against, if @type is KDBUS_MATCH_BLOOM
 * @bloom:		The bloom filter to match against, if @type is
 * 			KDBUS_MATCH_SRC_NAME or KDBUS_MATCH_NAME_*
 * @id:			The ID to match against, if @type is KDBUS_MATCH_ID_ADD
 * 			or KDBUS_MATCH_ID_REMOVE
 * @list_entry:		Entry in struct kdbus_match_db
 */
struct kdbus_match_db_entry_item {
	u64 type;
	union {
		char	*name;
		u64	*bloom;
		u64	id;
	};

	struct list_head	list_entry;
};

/**
 * struct kdbus_match_db_entry - a match database entry
 * @id:			The ID of the destination connection of this entry
 * @cookie:		User-supplied cookie to lookup the entry
 * @src_id:		The ID of the source connection to match against,
 * 			or KDBUS_MATCH_SRC_ID_ANY.
 * @list_entry:		The list entry element for the db list
 * @items_list:		The list head for tracking items to this entry
 */
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

/**
 * kdbus_match_db_unref() - drop a reference on a match database
 * @db:			The match database
 *
 * When the last reference is dropped, the database's internal memory
 * is freed.
 */
void kdbus_match_db_unref(struct kdbus_match_db *db)
{
	kref_put(&db->kref, __kdbus_match_db_free);
}

/**
 * kdbus_match_db_ref() - take a reference of a match database
 * @db:			The match database
 *
 * Returns: the database itself
 */
struct kdbus_match_db *kdbus_match_db_ref(struct kdbus_match_db *db)
{
	kref_get(&db->kref);
	return db;
}

/**
 * kdbus_match_db_new() - create a new match database
 * @db:			Pointer location for the returned database
 *
 * Returns 0 on success, any other value in case of errors.
 */
int kdbus_match_db_new(struct kdbus_match_db **db)
{
	struct kdbus_match_db *d;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	kref_init(&d->kref);
	mutex_init(&d->entries_lock);
	INIT_LIST_HEAD(&d->entries);

	*db = d;

	return 0;
}

static inline
bool kdbus_match_db_test_bloom(const u64 *filter,
			       const u64 *mask,
			       unsigned int n)
{
	size_t i;

	for (i = 0; i < n; i++)
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
bool kdbus_match_db_match_item(struct kdbus_match_db_entry *e,
			       struct kdbus_conn *conn_src,
			       struct kdbus_kmsg *kmsg)
{
	struct kdbus_match_db_entry_item *ei;

	list_for_each_entry(ei, &e->items_list, list_entry) {
		if (kmsg->bloom && ei->type == KDBUS_MATCH_BLOOM) {
			size_t n = conn_src->ep->bus->bloom_size / sizeof(u64);

			if (kdbus_match_db_test_bloom(kmsg->bloom,
						      ei->bloom, n))
				continue;

			return false;
		}

		if (kmsg->meta.src_names && ei->type == KDBUS_MATCH_SRC_NAME) {
			if (kdbus_match_db_test_src_names(kmsg->meta.src_names,
							  kmsg->meta.src_names_len,
							  ei->name))
				continue;

			return false;
		}
	}

	return true;
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
		if (e->src_id != KDBUS_MATCH_SRC_ID_ANY &&
		    e->src_id != conn_src->id)
			continue;

		matched = kdbus_match_db_match_item(e, conn_src, kmsg);
		if (matched)
			break;
	}
	mutex_unlock(&db->entries_lock);

	return matched;
}

static
bool kdbus_match_db_match_from_kernel(struct kdbus_match_db *db,
				      struct kdbus_kmsg *kmsg)
{
	u64 type = kmsg->notification_type;
	struct kdbus_match_db_entry *e;
	bool matched = false;

	mutex_lock(&db->entries_lock);
	list_for_each_entry(e, &db->entries, list_entry) {
		struct kdbus_match_db_entry_item *ei;

		list_for_each_entry(ei, &e->items_list, list_entry) {
			if (ei->id == 0 ||
			    ei->id == KDBUS_MATCH_SRC_ID_ANY ||
			    ei->id == e->src_id) {

				if (ei->type == KDBUS_MATCH_ID_ADD &&
				    type == KDBUS_ITEM_ID_ADD) {
					matched = true;
					break;
				}

				if (ei->type == KDBUS_MATCH_ID_REMOVE &&
				    type == KDBUS_ITEM_ID_REMOVE) {
					matched = true;
					break;
				}
			}

			if (e->src_id != KDBUS_MATCH_SRC_ID_ANY &&
			    e->src_id != 0)
				continue;

			if (ei->type == KDBUS_MATCH_NAME_ADD &&
			    type == KDBUS_ITEM_NAME_ADD) {
				matched = true;
				break;
			}

			if (ei->type == KDBUS_MATCH_NAME_CHANGE &&
			    type == KDBUS_ITEM_NAME_CHANGE) {
				matched = true;
				break;
			}

			if (ei->type == KDBUS_MATCH_NAME_REMOVE &&
			    type == KDBUS_ITEM_NAME_REMOVE) {
				matched = true;
				break;
			}
		}

		if (matched)
			break;
	}
	mutex_unlock(&db->entries_lock);

	return matched;
}

/**
 * kdbus_match_db_match_kmsg() - match a kmsg object agains the database entries
 * @db:			The match database
 * @conn_src:		The connection object originating the message
 * @kmsg:		The kmsg to perform the match on
 *
 * Returns true in if there was a matching database entry, false otherwise.
 */
bool kdbus_match_db_match_kmsg(struct kdbus_match_db *db,
			       struct kdbus_conn *conn_src,
			       struct kdbus_kmsg *kmsg)
{
	if (conn_src)
		return kdbus_match_db_match_with_src(db, conn_src, kmsg);
	else
		return kdbus_match_db_match_from_kernel(db, kmsg);
}

static int cmd_match_from_user(const struct kdbus_conn *conn,
			       void __user *buf, bool items,
			       struct kdbus_cmd_match **m)
{
	struct kdbus_cmd_match *cmd_match;
	u64 size;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_match))
		return -EFAULT;

	if (size < sizeof(*cmd_match) || size > KDBUS_MATCH_MAX_SIZE)
		return -EMSGSIZE;

	/* remove does not accept any items */
	if (!items && size != sizeof(*cmd_match))
		return -EMSGSIZE;

	cmd_match = memdup_user(buf, size);
	if (IS_ERR(cmd_match))
		return PTR_ERR(cmd_match);

	/* privileged users can act on behalf of someone else */
	if (cmd_match->id == 0)
		cmd_match->id = conn->id;
	else if (cmd_match->id != conn->id &&
		 !kdbus_bus_uid_is_privileged(conn->ep->bus))
			return -EPERM;

	*m = cmd_match;

	return 0;
}

/**
 * kdbus_match_db_add() - add an entry to the match database
 * @conn:		The connection that was used in the ioctl call
 * @buf:		The __user buffer that was provided along with the ioctl call
 *
 * Returns 0 in success, any other value in case of errors.
 * This function is used in the context of the KDBUS_CMD_MATCH_ADD ioctl
 * interface.
 */
int kdbus_match_db_add(struct kdbus_conn *conn, void __user *buf)
{
	struct kdbus_match_db *db;
	struct kdbus_cmd_match *cmd_match = NULL;
	struct kdbus_item *item;
	struct kdbus_match_db_entry *e;
	int ret;

	ret = cmd_match_from_user(conn, buf, true, &cmd_match);
	if (ret < 0)
		return ret;

	if (cmd_match->id != 0 && cmd_match->id != conn->id) {
		struct kdbus_conn *targ_conn;
		struct kdbus_bus *bus = conn->ep->bus;

		mutex_lock(&bus->lock);
		targ_conn = kdbus_bus_find_conn_by_id(bus, cmd_match->id);
		mutex_unlock(&bus->lock);

		if (!targ_conn) {
			ret = -ENXIO;
			goto exit_free;
		}

		db = kdbus_match_db_ref(targ_conn->match_db);
		kdbus_conn_unref(targ_conn);
	} else {
		/* ensure a ref'ed db after this block in any case */
		db = kdbus_match_db_ref(conn->match_db);
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		ret = -ENOMEM;
		goto exit_free;
	}

	mutex_lock(&db->entries_lock);
	INIT_LIST_HEAD(&e->list_entry);
	INIT_LIST_HEAD(&e->items_list);
	e->id = cmd_match->id;
	e->src_id = cmd_match->src_id;
	e->cookie = cmd_match->cookie;

	KDBUS_ITEM_FOREACH(item, cmd_match, items) {
		struct kdbus_match_db_entry_item *ei;
		size_t size;

		if (!KDBUS_ITEM_VALID(item, cmd_match)) {
			ret = -EINVAL;
			break;
		}

		ei = kzalloc(sizeof(*ei), GFP_KERNEL);
		if (!ei) {
			ret = -ENOMEM;
			break;
		}

		ei->type = item->type;
		INIT_LIST_HEAD(&ei->list_entry);
		size = item->size - offsetof(struct kdbus_item, data);

		switch (item->type) {
		case KDBUS_MATCH_BLOOM:
			if (size != conn->ep->bus->bloom_size) {
				ret = -EBADMSG;
				break;
			}

			ei->bloom = kmemdup(item->data, size, GFP_KERNEL);
			if (!ei->bloom)
				ret = -ENOMEM;
			break;

		case KDBUS_MATCH_SRC_NAME:
		case KDBUS_MATCH_NAME_ADD:
		case KDBUS_MATCH_NAME_REMOVE:
		case KDBUS_MATCH_NAME_CHANGE:
			if (size > 0) {
				ei->name = kstrdup(item->str, GFP_KERNEL);
				if (!ei->name)
					ret = -ENOMEM;
			}
			break;

		case KDBUS_MATCH_ID_ADD:
		case KDBUS_MATCH_ID_REMOVE:
			ei->id = item->id;
			break;
		}

		if (ret < 0)
			break;

		list_add_tail(&ei->list_entry, &e->items_list);
	}

	if (ret == 0 && !KDBUS_ITEM_END(item, cmd_match))
		ret = -EINVAL;

	if (ret >= 0)
		list_add_tail(&e->list_entry, &db->entries);
	else
		kdbus_match_db_entry_free(e);

	mutex_unlock(&db->entries_lock);
	kdbus_match_db_unref(db);

exit_free:
	kfree(cmd_match);
	return ret;
}

/**
 * kdbus_match_db_remove() - remove an entry from the match database
 * @conn:		The connection that was used in the ioctl call
 * @buf:		The __user buffer that was provided along with the ioctl call
 *
 * Returns 0 in success, any other value in case of errors.
 * This function is used in the context of the KDBUS_CMD_MATCH_REMOVE
 * ioctl interface.
 */
int kdbus_match_db_remove(struct kdbus_conn *conn, void __user *buf)
{
	struct kdbus_match_db *db;
	struct kdbus_cmd_match *cmd_match = NULL;
	struct kdbus_match_db_entry *e, *tmp;
	int ret;

	ret = cmd_match_from_user(conn, buf, false, &cmd_match);
	if (ret < 0)
		return ret;

	if (cmd_match->id != 0 && cmd_match->id != conn->id) {
		struct kdbus_conn *targ_conn;
		struct kdbus_bus *bus = conn->ep->bus;

		mutex_lock(&bus->lock);
		targ_conn = kdbus_bus_find_conn_by_id(bus, cmd_match->id);
		mutex_unlock(&bus->lock);

		if (targ_conn) {
			db = kdbus_match_db_ref(targ_conn->match_db);
			kdbus_conn_unref(targ_conn);
		} else {
			kfree(cmd_match);
			return -ENXIO;
		}
	} else {
		db = kdbus_match_db_ref(conn->match_db);
	}

	mutex_lock(&db->entries_lock);
	list_for_each_entry_safe(e, tmp, &db->entries, list_entry)
		if (e->cookie == cmd_match->cookie &&
		    e->id == cmd_match->id)
			kdbus_match_db_entry_free(e);
	mutex_unlock(&db->entries_lock);

	kdbus_match_db_unref(db);
	kfree(cmd_match);

	return 0;
}
