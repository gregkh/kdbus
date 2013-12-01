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
#include <linux/ctype.h>

#include "names.h"
#include "connection.h"
#include "notify.h"
#include "policy.h"
#include "bus.h"
#include "endpoint.h"
#include "metadata.h"

struct kdbus_name_queue_item {
	struct kdbus_conn	*conn;
	struct kdbus_name_entry	*entry;
	u64			 flags;
	struct list_head	 entry_entry;
	struct list_head	 conn_entry;
};

static void kdbus_name_entry_free(struct kdbus_name_entry *e)
{
	hash_del(&e->hentry);
	kfree(e->name);
	kfree(e);
}

static void __kdbus_name_registry_free(struct kref *kref)
{
	struct kdbus_name_entry *e;
	struct hlist_node *tmp;
	struct kdbus_name_registry *reg =
		container_of(kref, struct kdbus_name_registry, kref);
	unsigned int i;

	mutex_lock(&reg->entries_lock);
	hash_for_each_safe(reg->entries_hash, i, tmp, e, hentry)
		kdbus_name_entry_free(e);
	mutex_unlock(&reg->entries_lock);

	kfree(reg);
}

void kdbus_name_registry_unref(struct kdbus_name_registry *reg)
{
	kref_put(&reg->kref, __kdbus_name_registry_free);
}

struct kdbus_name_registry *kdbus_name_registry_new(void)
{
	struct kdbus_name_registry *reg;

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (!reg)
		return NULL;

	kref_init(&reg->kref);
	hash_init(reg->entries_hash);
	mutex_init(&reg->entries_lock);

	return reg;
}

static struct kdbus_name_entry *
__kdbus_name_lookup(struct kdbus_name_registry *reg,
		    u32 hash, const char *name)
{
	struct kdbus_name_entry *e;

	hash_for_each_possible(reg->entries_hash, e, hentry, hash)
		if (strcmp(e->name, name) == 0)
			return e;

	return NULL;
}

static void kdbus_name_queue_item_free(struct kdbus_name_queue_item *q)
{
	list_del(&q->entry_entry);
	list_del(&q->conn_entry);
	kfree(q);
}

static void kdbus_name_entry_detach(struct kdbus_name_entry *e)
{
	e->conn->names--;
	list_del(&e->conn_entry);
}

static void kdbus_name_entry_attach(struct kdbus_name_entry *e,
				    struct kdbus_conn *conn)
{
	e->conn = conn;
	list_add_tail(&e->conn_entry, &e->conn->names_list);
	conn->names++;
}

static void kdbus_name_entry_release(struct kdbus_name_entry *e)
{
	struct kdbus_name_queue_item *q;

	kdbus_name_entry_detach(e);

	if (list_empty(&e->queue_list)) {
		if (e->starter) {
			kdbus_notify_name_change(e->conn->ep, KDBUS_ITEM_NAME_CHANGE,
						 e->conn->id, e->starter->id,
						 e->flags, e->name);
			kdbus_name_entry_attach(e, e->starter);
		} else {
			kdbus_notify_name_change(e->conn->ep, KDBUS_ITEM_NAME_REMOVE,
						 e->conn->id, 0, e->flags, e->name);
			kdbus_name_entry_free(e);
		}
	} else {
		struct kdbus_conn *old_conn = e->conn;

		q = list_first_entry(&e->queue_list,
				     struct kdbus_name_queue_item,
				     entry_entry);
		e->flags = q->flags;
		kdbus_name_entry_attach(e, q->conn);
		kdbus_name_queue_item_free(q);
		kdbus_notify_name_change(old_conn->ep, KDBUS_ITEM_NAME_CHANGE,
					 old_conn->id, e->conn->id,
					 e->flags, e->name);
	}
}

int kdbus_name_release(struct kdbus_name_entry *e, struct kdbus_conn *conn)
{
	struct kdbus_name_queue_item *q_tmp, *q;

	if (e->conn == conn) {
		kdbus_name_entry_release(e);
		return 0;
	}

	/* remove queued name */
	list_for_each_entry_safe(q, q_tmp, &e->queue_list, entry_entry) {
		if (q->conn != conn)
			continue;
		kdbus_name_queue_item_free(q);
		return 0;
	}

	return -EPERM;
}

void kdbus_name_remove_by_conn(struct kdbus_name_registry *reg,
			       struct kdbus_conn *conn)
{
	struct kdbus_name_entry *e_tmp, *e;
	struct kdbus_name_queue_item *q_tmp, *q;

	mutex_lock(&reg->entries_lock);
	mutex_lock(&conn->names_lock);

	list_for_each_entry_safe(q, q_tmp, &conn->names_queue_list, conn_entry)
		kdbus_name_queue_item_free(q);

	list_for_each_entry_safe(e, e_tmp, &conn->names_list, conn_entry)
		kdbus_name_entry_release(e);

	mutex_unlock(&conn->names_lock);
	mutex_unlock(&reg->entries_lock);
}

struct kdbus_name_entry *kdbus_name_lookup(struct kdbus_name_registry *reg,
					   const char *name)
{
	struct kdbus_name_entry *e = NULL;
	u32 hash = kdbus_str_hash(name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, name);
	mutex_unlock(&reg->entries_lock);

	return e;
}

static int kdbus_name_queue_conn(struct kdbus_conn *conn, u64 *flags,
				 struct kdbus_name_entry *e)
{
	struct kdbus_name_queue_item *q;

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	q->conn = conn;
	q->flags = *flags;

	list_add_tail(&q->entry_entry, &e->queue_list);
	list_add_tail(&q->conn_entry, &conn->names_queue_list);
	*flags |= KDBUS_NAME_IN_QUEUE;

	return 0;
}

/* called with entries_lock held */
static int kdbus_name_handle_conflict(struct kdbus_name_registry *reg,
				      struct kdbus_conn *conn,
				      struct kdbus_name_entry *e, u64 *flags)
{
	u64 old_id;

	if (conn->flags & KDBUS_HELLO_STARTER) {
		if (e->starter == NULL) {
			e->starter = conn;
			return 0;
		} else {
			return -EBUSY;
		}
	}

	if (((*flags & KDBUS_NAME_REPLACE_EXISTING) &&
	     (e->flags & KDBUS_NAME_ALLOW_REPLACEMENT)) ||
	    ((e->starter == e->conn) && e->starter != conn)) {
		if (e->flags & KDBUS_NAME_QUEUE &&
		    kdbus_name_queue_conn(e->conn, &e->flags, e) < 0)
				return -ENOMEM;
		old_id = e->conn->id;
		kdbus_name_entry_detach(e);
		kdbus_name_entry_attach(e, conn);
		e->flags = *flags;

		return kdbus_notify_name_change(conn->ep, KDBUS_ITEM_NAME_CHANGE,
						old_id, conn->id, *flags,
						e->name);
	}

	if (*flags & KDBUS_NAME_QUEUE)
		return kdbus_name_queue_conn(conn, flags, e);

	return -EEXIST;
}

bool kdbus_name_is_valid(const char *p)
{
	const char *q;
	bool dot, found_dot;

	for (dot = true, q = p; *q; q++) {
		if (*q == '.') {
			if (dot)
				return false;

			found_dot = dot = true;
		} else {
			bool good;

			good = isalpha(*q) || (!dot && isdigit(*q)) ||
				*q == '_' || *q == '-';

			if (!good)
				return false;

			dot = false;
		}
	}

	if (q - p > KDBUS_NAME_MAX_LEN)
		return false;

	if (dot)
		return false;

	if (!found_dot)
		return false;

	return true;
}

int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       const char *name, u64 flags,
		       struct kdbus_name_entry **entry)
{
	struct kdbus_name_entry *e = NULL;
	int ret = 0;
	u32 hash;

	hash = kdbus_str_hash(name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, name);
	if (e) {
		if (e->conn == conn) {
			e->flags = flags;
			ret = -EALREADY;
			goto exit_unlock;
		} else {
			ret = kdbus_name_handle_conflict(reg, conn, e, &flags);
			if (ret < 0)
				goto exit_unlock;
		}

		goto exit_unlock;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	e->name = kstrdup(name, GFP_KERNEL);
	if (!e->name) {
		kfree(e);
		ret = -ENOMEM;
		goto exit_unlock;
	}

	if (flags & KDBUS_HELLO_STARTER)
		e->starter = conn;

	e->flags = flags;
	INIT_LIST_HEAD(&e->queue_list);
	INIT_LIST_HEAD(&e->conn_entry);
	hash_add(reg->entries_hash, &e->hentry, hash);
	kdbus_name_entry_attach(e, conn);

	kdbus_notify_name_change(e->conn->ep, KDBUS_ITEM_NAME_ADD, 0,
				 e->conn->id, e->flags, e->name);

	if (entry)
		*entry = e;

exit_unlock:
	mutex_lock(&reg->entries_lock);
	return ret;
}

int kdbus_cmd_name_acquire(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   void __user *buf)
{
	struct kdbus_name_entry *e = NULL;
	struct kdbus_cmd_name *cmd_name;
	u64 size;
	u32 hash;
	int ret = 0;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_name))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name)) ||
	    (size > (sizeof(struct kdbus_cmd_name) + KDBUS_NAME_MAX_LEN + 1)))
		return -EMSGSIZE;

	if (conn->names > KDBUS_CONN_MAX_NAMES)
		return -E2BIG;

	cmd_name = memdup_user(buf, size);
	if (IS_ERR(cmd_name))
		return PTR_ERR(cmd_name);

	if (!kdbus_name_is_valid(cmd_name->name)) {
		ret = -EINVAL;
		goto exit_free;
	}

	/* privileged users can act on behalf of someone else */
	if (cmd_name->id > 0) {
		struct kdbus_conn *new_conn;

		if (!kdbus_bus_uid_is_privileged(conn->ep->bus)) {
			ret = -EPERM;
			goto exit_free;
		}

		new_conn = kdbus_bus_find_conn_by_id(conn->ep->bus, cmd_name->id);
		if (!new_conn) {
			ret = -ENXIO;
			goto exit_free;
		}

		conn = new_conn;
	}

	cmd_name->flags &= ~KDBUS_NAME_IN_QUEUE;
	hash = kdbus_str_hash(cmd_name->name);

	if (conn->ep->policy_db) {
		ret = kdbus_policy_db_check_own_access(conn->ep->policy_db,
						       conn, cmd_name->name);
		if (ret < 0)
			goto exit_free;
	}

	ret = kdbus_name_acquire(reg, conn, cmd_name->name,
				 cmd_name->flags, &e);
	if (ret < 0)
		goto exit_unlock;

	if (copy_to_user(buf, cmd_name, size)) {
		ret = -EFAULT;
		goto exit_unlock_free;
	}

	kfree(cmd_name);
	mutex_unlock(&reg->entries_lock);
	return 0;

exit_unlock_free:
	kdbus_name_entry_release(e);

exit_unlock:
	mutex_unlock(&reg->entries_lock);

exit_free:
	kfree(cmd_name);
	return ret;
}

int kdbus_cmd_name_release(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   void __user *buf)
{
	struct kdbus_name_entry *e;
	struct kdbus_cmd_name *cmd_name;
	u64 size;
	u32 hash;
	int ret = 0;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_name))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name)) ||
	    (size > (sizeof(struct kdbus_cmd_name) + KDBUS_NAME_MAX_LEN + 1)))
		return -EMSGSIZE;

	cmd_name = memdup_user(buf, size);
	if (IS_ERR(cmd_name))
		return PTR_ERR(cmd_name);

	if (!kdbus_name_is_valid(cmd_name->name)) {
		ret = -EINVAL;
		goto exit_free;
	}

	hash = kdbus_str_hash(cmd_name->name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, cmd_name->name);
	if (!e) {
		ret = -ESRCH;
		goto exit_unlock;
	}

	/* privileged users can act on behalf of someone else */
	if (e->conn != conn) {
		if (!kdbus_bus_uid_is_privileged(conn->ep->bus)) {
			ret = -EPERM;
			goto exit_unlock;
		}
		conn = kdbus_bus_find_conn_by_id(conn->ep->bus, cmd_name->id);
	}

	ret = kdbus_name_release(e, conn);

exit_unlock:
	mutex_unlock(&reg->entries_lock);

exit_free:
	kfree(cmd_name);
	return ret;
}

int kdbus_cmd_name_list(struct kdbus_name_registry *reg,
			struct kdbus_conn *conn,
			void __user *buf)
{
	struct kdbus_cmd_name_list *cmd_list;
	struct kdbus_name_list list = {};
	struct kdbus_name_entry *e;
	struct kdbus_bus *bus = conn->ep->bus;
	size_t size;
	u64 tmp;
	size_t off, pos;
	int ret = 0;

	cmd_list = memdup_user(buf, sizeof(struct kdbus_cmd_name_list));
	if (IS_ERR(cmd_list))
		return PTR_ERR(cmd_list);

	mutex_lock(&reg->entries_lock);

	/* calculate size */
	size = sizeof(struct kdbus_name_list);
	hash_for_each(reg->entries_hash, tmp, e, hentry)
		size += KDBUS_ALIGN8(sizeof(struct kdbus_cmd_name) +
				     strlen(e->name) + 1);

	if (cmd_list->flags & KDBUS_NAME_LIST_UNIQUE_NAMES) {
		struct kdbus_conn *c;
		int i;

		hash_for_each(bus->conn_hash, i, c, hentry)
			size += KDBUS_ALIGN8(sizeof(struct kdbus_cmd_name));
	}

	ret = kdbus_pool_alloc(conn->pool, size, &off);
	if (ret < 0)
		goto exit_unlock;

	/* copy header */
	pos = off;
	list.size = size;
	ret = kdbus_pool_write(conn->pool, pos,
			       &list, sizeof(struct kdbus_name_list));
	if (ret < 0) {
		kdbus_pool_free(conn->pool, off);
		goto exit_unlock;
	}
	pos += sizeof(struct kdbus_name_list);

	/* copy names */
	hash_for_each(reg->entries_hash, tmp, e, hentry) {
		struct kdbus_cmd_name cmd_name = {};
		size_t len;

		cmd_name.size = sizeof(struct kdbus_cmd_name) +
				strlen(e->name) + 1;
		cmd_name.flags = e->flags;
		cmd_name.id = e->conn->id;

		ret = kdbus_pool_write(conn->pool, pos,
				       &cmd_name, sizeof(struct kdbus_cmd_name));
		if (ret < 0) {
			kdbus_pool_free(conn->pool, off);
			goto exit_unlock;
		}
		pos += sizeof(struct kdbus_cmd_name);

		len = strlen(e->name) + 1;
		ret = kdbus_pool_write(conn->pool, pos, e->name, len);
		if (ret < 0) {
			kdbus_pool_free(conn->pool, off);
			goto exit_unlock;
		}

		pos += KDBUS_ALIGN8(len);
	}

	/*
	 * If the listing of unique names is requested, iterate over the
	 * bus' connections and find those which do not have a well-known name
	 * assigned to it.
	 */
	if (cmd_list->flags & KDBUS_NAME_LIST_UNIQUE_NAMES) {
		struct kdbus_conn *c;
		int i;

		hash_for_each(bus->conn_hash, i, c, hentry) {
			struct kdbus_cmd_name cmd_name = {};

			cmd_name.size = sizeof(struct kdbus_cmd_name);
			cmd_name.id = c->id;
			cmd_name.flags = c->flags;

			ret = kdbus_pool_write(conn->pool, pos,
					       &cmd_name, sizeof(struct kdbus_cmd_name));
			if (ret < 0) {
				kdbus_pool_free(conn->pool, off);
				goto exit_unlock;
			}

			pos += KDBUS_ALIGN8(sizeof(struct kdbus_cmd_name));
		}
	}

	if (kdbus_offset_set_user(&off, buf, struct kdbus_cmd_name_list)) {
		ret = -EFAULT;
		kdbus_pool_free(conn->pool, off);
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&reg->entries_lock);
	kfree(cmd_list);

	return ret;
}

int kdbus_cmd_name_info(struct kdbus_name_registry *reg,
			struct kdbus_conn *conn,
			void __user *buf)
{
	struct kdbus_cmd_name_info *cmd_info;
	struct kdbus_name_info info = {};
	struct kdbus_conn *owner_conn = NULL;
	struct kdbus_name_entry *e = NULL;
	u64 size;
	u32 hash;
	char *name = NULL;
	size_t off;
	int ret = 0;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_name_info))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_name_info))
		return -EINVAL;

	if (size > sizeof(struct kdbus_cmd_name_info) + KDBUS_NAME_MAX_LEN + 1)
		return -EMSGSIZE;

	cmd_info = memdup_user(buf, size);
	if (IS_ERR(cmd_info))
		return PTR_ERR(cmd_info);

	/* The API offers to look up a connection by ID or by name */
	if (cmd_info->id != 0) {
		owner_conn = kdbus_bus_find_conn_by_id(conn->ep->bus,
						       cmd_info->id);
	} else {
		if (size == sizeof(struct kdbus_cmd_name_info)) {
			ret = -EINVAL;
			goto exit_free;
		}

		if (!kdbus_name_is_valid(cmd_info->name)) {
			ret = -EINVAL;
			goto exit_free;
		}

		name = cmd_info->name;
		hash = kdbus_str_hash(name);
	}

	mutex_lock(&reg->entries_lock);
	/*
	 * If a lookup by name was requested, set owner_conn to the
	 * matching entry's connection pointer. Otherwise, owner_conn
	 * was already set above.
	 */
	if (name) {
		e = __kdbus_name_lookup(reg, hash, name);
		if (!e) {
			ret = -ENOENT;
			goto exit_unlock;
		}

		owner_conn = e->conn;
	}

	if (!owner_conn) {
		ret = -ENXIO;
		goto exit_unlock;
	}

	if (owner_conn->meta.size == 0)
		goto exit_unlock;

	info.size = sizeof(struct kdbus_name_info) + owner_conn->meta.size;
	info.id = owner_conn->id;
	if (e)
		cmd_info->flags = e->flags;

	ret = kdbus_pool_alloc(conn->pool, info.size, &off);
	if (ret < 0)
		goto exit_unlock;

	ret = kdbus_pool_write(conn->pool, off,
			       &info, sizeof(struct kdbus_name_info));
	if (ret < 0) {
		kdbus_pool_free(conn->pool, off);
		goto exit_unlock;
	}

	ret = kdbus_pool_write(conn->pool, off + sizeof(struct kdbus_name_info),
			       owner_conn->meta.data, owner_conn->meta.size);
	if (ret < 0) {
		kdbus_pool_free(conn->pool, off);
		goto exit_unlock;
	}

	if (kdbus_offset_set_user(&off, buf, struct kdbus_cmd_name_info)) {
		ret = -EFAULT;
		kdbus_pool_free(conn->pool, off);
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&reg->entries_lock);

exit_free:
	kfree(cmd_info);
	return ret;
}
