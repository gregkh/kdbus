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
#include "kdbus.h"

#include "kdbus_internal.h"

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
	int i;

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

static u32 kdbus_name_make_hash(const char *name)
{
	unsigned int len = strlen(name);
	u32 hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(*name++, hash);

	return end_name_hash(hash);
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
	list_del(&e->conn_entry);
}

static void kdbus_name_entry_attach(struct kdbus_name_entry *e,
				    struct kdbus_conn *conn)
{
	e->conn = conn;
	list_add_tail(&e->conn_entry, &e->conn->names_list);
}

static void kdbus_name_entry_release(struct kdbus_name_entry *e)
{
	struct kdbus_name_queue_item *q;

	kdbus_name_entry_detach(e);

	if (list_empty(&e->queue_list)) {
		if (e->starter) {
			kdbus_notify_name_change(e->conn->ep, KDBUS_MSG_NAME_CHANGE,
						 e->conn->id, e->starter->id,
						 e->flags, e->name);
			e->conn = e->starter;
		} else {
			kdbus_notify_name_change(e->conn->ep, KDBUS_MSG_NAME_REMOVE,
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
		kdbus_notify_name_change(old_conn->ep, KDBUS_MSG_NAME_CHANGE,
				old_conn->id, e->conn->id, e->flags, e->name);
	}
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
					   const char *name, u64 flags)
{
	struct kdbus_name_entry *e = NULL;
	u32 hash = kdbus_name_make_hash(name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, name);
	mutex_unlock(&reg->entries_lock);

	return e;
}


/* called with entries_lock held! */
static int kdbus_name_handle_conflict(struct kdbus_name_registry *reg,
				      struct kdbus_conn *conn,
				      struct kdbus_name_entry *e, u64 *flags)
{
	if (conn->flags & KDBUS_CMD_HELLO_STARTER) {
		if (e->starter == NULL) {
			e->starter = conn;
			return 0;
		} else {
			return -EBUSY;
		}
	}

	if (((*flags   & KDBUS_CMD_NAME_REPLACE_EXISTING) &&
	     (e->flags & KDBUS_CMD_NAME_ALLOW_REPLACEMENT)) ||
	     (e->starter && e->starter != conn)) {
		kdbus_name_entry_detach(e);
		kdbus_name_entry_attach(e, conn);

		return kdbus_notify_name_change(conn->ep, KDBUS_MSG_NAME_CHANGE,
						e->conn->id, conn->id, *flags,
						e->name);
	}

	if (*flags & KDBUS_CMD_NAME_QUEUE) {
		struct kdbus_name_queue_item *q;

		q = kzalloc(sizeof(*q), GFP_KERNEL);
		if (!q)
			return -ENOMEM;

		q->conn = conn;
		q->flags = *flags;
		INIT_LIST_HEAD(&q->entry_entry);

		list_add_tail(&q->entry_entry, &e->queue_list);
		list_add_tail(&q->conn_entry, &conn->names_queue_list);
		*flags |= KDBUS_CMD_NAME_IN_QUEUE;

		return 0;
	}

	return -EEXIST;
}

bool kdbus_name_is_valid(const char *p)
{
	const char *q;
	bool dot, found_dot;

	for (dot = true, q = p; *q; q++) {
		if (!isascii(*q))
			return false;

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

	if (q - p > 255)
		return false;

	if (dot)
		return false;

	if (!found_dot)
		return false;

	return true;
}
/* IOCTL interface */

int kdbus_cmd_name_acquire(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   void __user *buf)
{
	struct kdbus_name_entry *e = NULL;
	struct kdbus_cmd_name *cmd_name;
	u64 size;
	u32 hash;
	int ret = 0;

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_name))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name)) ||
	    (size > (sizeof(struct kdbus_cmd_name) + 256)))
		return -EMSGSIZE;

	cmd_name = memdup_user(buf, size);
	if (IS_ERR(cmd_name))
		return PTR_ERR(cmd_name);

	if (!kdbus_name_is_valid(cmd_name->name))
		return -EINVAL;

	cmd_name->name_flags &= ~KDBUS_CMD_NAME_IN_QUEUE;
	hash = kdbus_name_make_hash(cmd_name->name);

	if (conn->ep->policy_db) {
		ret = kdbus_policy_db_check_own_access(conn->ep->policy_db,
						       conn, cmd_name->name);
		if (ret < 0)
			return ret;
	}

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, cmd_name->name);
	if (e) {
		if (e->conn == conn) {
			/* just update flags */
			e->flags = cmd_name->name_flags;
		} else {
			ret = kdbus_name_handle_conflict(reg, conn, e,
							 &cmd_name->name_flags);
			if (ret < 0)
				goto err_unlock;
		}

		goto exit_copy;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		ret = -ENOMEM;
		goto err_unlock_free;
	}

	e->name = kstrdup(cmd_name->name, GFP_KERNEL);
	if (!e->name) {
		ret = -ENOMEM;
		goto err_unlock_free;
	}

	if (conn->flags & KDBUS_CMD_HELLO_STARTER)
		e->starter = conn;

	e->flags = cmd_name->name_flags;
	INIT_LIST_HEAD(&e->queue_list);
	INIT_LIST_HEAD(&e->conn_entry);

	hash_add(reg->entries_hash, &e->hentry, hash);
	kdbus_name_entry_attach(e, conn);

exit_copy:
	if (copy_to_user(buf, cmd_name, size)) {
		ret = -EFAULT;
		goto err_unlock_free;
	}

	kdbus_notify_name_change(e->conn->ep, KDBUS_MSG_NAME_ADD, 0,
				 e->conn->id, e->flags, e->name);

	kfree(cmd_name);
	mutex_unlock(&reg->entries_lock);
	return 0;

err_unlock_free:
	kfree(cmd_name);
	kdbus_name_entry_release(e);

err_unlock:
	mutex_unlock(&reg->entries_lock);

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

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_name))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name)) ||
	    (size > (sizeof(struct kdbus_cmd_name) + 256)))
		return -EMSGSIZE;

	cmd_name = memdup_user(buf, size);
	if (IS_ERR(cmd_name))
		return PTR_ERR(cmd_name);

	if (!kdbus_name_is_valid(cmd_name->name))
		return -EINVAL;

	hash = kdbus_name_make_hash(cmd_name->name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, cmd_name->name);
	if (!e)
		ret = -ENXIO;
	else if (e->conn != conn)
		ret = -EPERM;
	else
		kdbus_name_entry_release(e);
	mutex_unlock(&reg->entries_lock);

	kfree(cmd_name);

	return ret;
}

int kdbus_cmd_name_list(struct kdbus_name_registry *reg,
			struct kdbus_conn *conn,
			void __user *buf)
{
	struct kdbus_cmd_names *cmd_names = NULL;
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_name_entry *e;
	u64 user_size, size = 0, tmp;
	int ret = 0;

	if (kdbus_size_get_user(user_size, buf, struct kdbus_cmd_names))
		return -EFAULT;

	mutex_lock(&reg->entries_lock);

	size = sizeof(struct kdbus_cmd_names);

	hash_for_each(reg->entries_hash, tmp, e, hentry)
		size += sizeof(struct kdbus_cmd_name) + strlen(e->name) + 1;

	if (size > user_size) {
		kdbus_size_set_user(size, buf, struct kdbus_cmd_names);
		ret = -ENOBUFS;
		goto exit_unlock;
	}

	cmd_names = kzalloc(size, GFP_KERNEL);
	if (!cmd_names) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	cmd_names->size = size;
	cmd_name = cmd_names->names;

	hash_for_each(reg->entries_hash, tmp, e, hentry) {
		cmd_name->size = sizeof(struct kdbus_cmd_name) + strlen(e->name) + 1;
		cmd_name->name_flags = 0; /* FIXME */
		cmd_name->id = e->conn->id;
		strcpy(cmd_name->name, e->name);
		cmd_name = (struct kdbus_cmd_name *) ((u8 *) cmd_name + cmd_name->size);
	}

	if (copy_to_user(buf, cmd_names, size)) {
		ret = -EFAULT;
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&reg->entries_lock);
	kfree(cmd_names);

	return ret;
}

int kdbus_cmd_name_query(struct kdbus_name_registry *reg,
			 struct kdbus_conn *conn,
			 void __user *buf)
{
	struct kdbus_name_entry *e;
	struct kdbus_cmd_name_info *cmd_name_info;
	u64 size;
	u64 tmp;
	int ret = 0;

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_name_info))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name_info)) ||
	    (size > (sizeof(struct kdbus_cmd_name_info) + 256)))
		return -EMSGSIZE;

	cmd_name_info = memdup_user(buf, size);
	if (IS_ERR(cmd_name_info))
		return PTR_ERR(cmd_name_info);

	if (cmd_name_info->id == 0) {
		// FIXME, look up by name, not id
		kfree(cmd_name_info);
		return -ENOSYS;
	}

	mutex_lock(&reg->entries_lock);
	hash_for_each(reg->entries_hash, tmp, e, hentry) {
		if (e->conn->id == cmd_name_info->id) {
			/* found the id, but wait, how are we supposed to get
			 * the data back to userspace? */
			// FIXME
			break;
		}
	}
	mutex_unlock(&reg->entries_lock);

	kfree(cmd_name_info);

	return ret;
}

