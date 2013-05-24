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
					   const char *name)
{
	struct kdbus_name_entry *e = NULL;
	u32 hash = kdbus_str_hash(name);

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
	if (conn->flags & KDBUS_HELLO_STARTER) {
		if (e->starter == NULL) {
			e->starter = conn;
			return 0;
		} else {
			return -EBUSY;
		}
	}

	if (((*flags   & KDBUS_NAME_REPLACE_EXISTING) &&
	     (e->flags & KDBUS_NAME_ALLOW_REPLACEMENT)) ||
	     (e->starter && e->starter != conn)) {
		kdbus_name_entry_detach(e);
		kdbus_name_entry_attach(e, conn);

		return kdbus_notify_name_change(conn->ep, KDBUS_MSG_NAME_CHANGE,
						e->conn->id, conn->id, *flags,
						e->name);
	}

	if (*flags & KDBUS_NAME_QUEUE) {
		struct kdbus_name_queue_item *q;

		q = kzalloc(sizeof(*q), GFP_KERNEL);
		if (!q)
			return -ENOMEM;

		q->conn = conn;
		q->flags = *flags;
		INIT_LIST_HEAD(&q->entry_entry);

		list_add_tail(&q->entry_entry, &e->queue_list);
		list_add_tail(&q->conn_entry, &conn->names_queue_list);
		*flags |= KDBUS_NAME_IN_QUEUE;

		return 0;
	}

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

	cmd_name = memdup_user(buf, size);
	if (IS_ERR(cmd_name))
		return PTR_ERR(cmd_name);

	if (!kdbus_name_is_valid(cmd_name->name))
		return -EINVAL;

	/* privileged users can act on behalf of someone else */
	if (cmd_name->id > 0) {
		struct kdbus_conn *new_conn;

		new_conn = kdbus_bus_find_conn_by_id(conn->ep->bus, cmd_name->id);
		if (!new_conn)
			return -ENXIO;

		if (conn->creds.uid != new_conn->creds.uid &&
		    !kdbus_bus_uid_is_privileged(conn->ep->bus))
			return -EPERM;

		conn = new_conn;
	}

	cmd_name->flags &= ~KDBUS_NAME_IN_QUEUE;
	hash = kdbus_str_hash(cmd_name->name);

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
			e->flags = cmd_name->flags;
		} else {
			ret = kdbus_name_handle_conflict(reg, conn, e,
							 &cmd_name->flags);
			if (ret < 0)
				goto exit_unlock;
		}

		goto exit_copy;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		ret = -ENOMEM;
		goto exit_unlock_free;
	}

	e->name = kstrdup(cmd_name->name, GFP_KERNEL);
	if (!e->name) {
		ret = -ENOMEM;
		goto exit_unlock_free;
	}

	if (conn->flags & KDBUS_HELLO_STARTER)
		e->starter = conn;

	e->flags = cmd_name->flags;
	INIT_LIST_HEAD(&e->queue_list);
	INIT_LIST_HEAD(&e->conn_entry);

	hash_add(reg->entries_hash, &e->hentry, hash);
	kdbus_name_entry_attach(e, conn);

exit_copy:
	if (copy_to_user(buf, cmd_name, size)) {
		ret = -EFAULT;
		goto exit_unlock_free;
	}

	kdbus_notify_name_change(e->conn->ep, KDBUS_MSG_NAME_ADD, 0,
				 e->conn->id, e->flags, e->name);

	kfree(cmd_name);
	mutex_unlock(&reg->entries_lock);
	return 0;

exit_unlock_free:
	kfree(cmd_name);
	kdbus_name_entry_release(e);

exit_unlock:
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

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_name))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name)) ||
	    (size > (sizeof(struct kdbus_cmd_name) + KDBUS_NAME_MAX_LEN + 1)))
		return -EMSGSIZE;

	cmd_name = memdup_user(buf, size);
	if (IS_ERR(cmd_name))
		return PTR_ERR(cmd_name);

	if (!kdbus_name_is_valid(cmd_name->name))
		return -EINVAL;

	hash = kdbus_str_hash(cmd_name->name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, cmd_name->name);
	if (!e)
		ret = -ESRCH;
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

	if (kdbus_size_get_user(&user_size, buf, struct kdbus_cmd_names))
		return -EFAULT;

	mutex_lock(&reg->entries_lock);

	size = sizeof(struct kdbus_cmd_names);

	hash_for_each(reg->entries_hash, tmp, e, hentry)
		size += KDBUS_ALIGN8(sizeof(struct kdbus_cmd_name) +
				     strlen(e->name) + 1);

	if (size > user_size) {
		kdbus_size_set_user(&size, buf, struct kdbus_cmd_names);
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
		cmd_name->size = sizeof(struct kdbus_cmd_name) +
				 strlen(e->name) + 1;
		cmd_name->flags = e->flags;
		cmd_name->id = e->conn->id;
		strcpy(cmd_name->name, e->name);
		cmd_name = KDBUS_PART_NEXT(cmd_name);
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

static int
kdbus_name_fill_info_items(struct kdbus_conn *conn,
			   struct kdbus_item *item,
			   size_t *size)
{
	int ret = 0;
	size_t size_req = 0;
	size_t size_avail = *size;

#ifdef CONFIG_AUDITSYSCALL
	size_req += KDBUS_ITEM_SIZE(sizeof(conn->audit_ids));
#endif

#ifdef CONFIG_SECURITY
	size_req += KDBUS_ITEM_SIZE(conn->sec_label_len + 1);
#endif
	*size = size_req;
	if (size_avail < size_req)
		return -ENOBUFS;

#ifdef CONFIG_AUDITSYSCALL
	item->size = KDBUS_PART_HEADER_SIZE + sizeof(conn->audit_ids);
	item->type = KDBUS_NAME_INFO_ITEM_AUDIT;
	memcpy(item->data, conn->audit_ids, sizeof(conn->audit_ids));
	item = KDBUS_PART_NEXT(item);
#endif

#ifdef CONFIG_SECURITY
	item->size = KDBUS_PART_HEADER_SIZE + conn->sec_label_len + 1;
	item->type = KDBUS_NAME_INFO_ITEM_SECLABEL;
	memcpy(item->data, conn->sec_label, conn->sec_label_len);
	item = KDBUS_PART_NEXT(item);
#endif
	return ret;
}

int kdbus_cmd_name_query(struct kdbus_name_registry *reg,
			 struct kdbus_conn *conn,
			 void __user *buf)
{
	struct kdbus_name_entry *e = NULL;
	struct kdbus_cmd_name_info *cmd_name_info;
	struct kdbus_item *info_item;
	struct kdbus_conn *owner_conn;
	size_t extra_size;
	u64 size;
	u32 hash;
	int ret = 0;
	char *name = NULL;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_name_info))
		return -EFAULT;

	if ((size < sizeof(struct kdbus_cmd_name_info)) ||
	    (size > (sizeof(struct kdbus_cmd_name_info) + KDBUS_NAME_MAX_LEN + 1)))
		return -EMSGSIZE;

	cmd_name_info = memdup_user(buf, size);
	if (IS_ERR(cmd_name_info))
		return PTR_ERR(cmd_name_info);

	/* The API offers to look up a connection by ID or by name */
	if (cmd_name_info->id != 0) {
		owner_conn = kdbus_bus_find_conn_by_id(conn->ep->bus,
						       cmd_name_info->id);
		if (!owner_conn)
			return -ENXIO;
	} else {
		KDBUS_PART_FOREACH(info_item, cmd_name_info, items) {
			if (!KDBUS_PART_VALID(info_item, cmd_name_info))
				return -EINVAL;

			if (name)
				return -EBADMSG;

			if (info_item->type == KDBUS_NAME_INFO_ITEM_NAME)
				name = info_item->data;
		}

		if (!KDBUS_PART_END(info_item, cmd_name_info))
			return -EINVAL;

		if (!name)
			return -EINVAL;

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

	extra_size = size - offsetof(struct kdbus_cmd_name_info, items);

	ret = kdbus_name_fill_info_items(owner_conn, cmd_name_info->items, &extra_size);
	size = offsetof(struct kdbus_cmd_name_info, items) + extra_size;
	if (ret < 0) {
		/* let the user know how much space we require */
		kdbus_size_set_user(&size, buf, struct kdbus_cmd_name_info);
		goto exit_unlock;
	}

	cmd_name_info->size = size;
	cmd_name_info->id = owner_conn->id;
	if (e)
		cmd_name_info->flags = e->flags;
	memcpy(&cmd_name_info->creds, &owner_conn->creds,
	       sizeof(cmd_name_info->creds));

	ret = copy_to_user(buf, cmd_name_info, size);

exit_unlock:
	mutex_unlock(&reg->entries_lock);

	kfree(cmd_name_info);

	return ret;
}

