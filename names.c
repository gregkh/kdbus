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

#define KDBUS_MSG_DATA_SIZE(SIZE) \
	ALIGN((SIZE) + offsetof(struct kdbus_msg_data, data), sizeof(u64))

static void __kdbus_name_registry_free(struct kref *kref)
{
	struct kdbus_name_registry *reg =
		container_of(kref, struct kdbus_name_registry, kref);
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

static u64 kdbus_name_make_hash(const char *name)
{
	unsigned int len = strlen(name);
	u64 hash = init_name_hash();

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

static void kdbus_name_add_to_conn(struct kdbus_name_entry *e,
				   struct kdbus_conn *conn)
{
	e->conn = conn;
	list_add_tail(&e->conn_entry, &conn->names_list);
}

static int kdbus_name_send_name_changed_msg(struct kdbus_conn *old,
					    struct kdbus_conn *new,
					    struct kdbus_name_entry *e)
{
	struct kdbus_kmsg *kmsg;
	struct kdbus_msg_data *data;
	struct kdbus_manager_msg_name_change *name_change;
	u64 extra_size = sizeof(*name_change) + strlen(e->name) + 1;
	int ret;

	ret = kdbus_kmsg_new(new, extra_size, &kmsg);
	if (ret < 0)
		return ret;

	/* FIXME: broadcast? */
	kmsg->msg.dst_id = KDBUS_DST_ID_BROADCAST;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;

	data = kmsg->msg.data;
	data->type = KDBUS_MSG_NAME_CHANGE;
	name_change = &data->name_change;

	name_change->old_id = old->id;
	name_change->new_id = new->id;
	name_change->flags = e->flags;
	strcpy(name_change->name, e->name);

	ret = kdbus_kmsg_send(new->ep, &kmsg);
	kdbus_kmsg_unref(kmsg);

	return ret;
}

static void kdbus_name_queue_item_free(struct kdbus_name_queue_item *q)
{
	list_del(&q->entry_entry);
	list_del(&q->conn_entry);
	kfree(q);
}

static int kdbus_name_entry_release(struct kdbus_name_entry *e)
{
	struct kdbus_name_queue_item *q;
	int ret = 0;

	list_del(&e->conn_entry);

	if (list_empty(&e->queue_list)) {
		kfree(e->name);
		kfree(e);
	} else {
		struct kdbus_conn *old_conn = e->conn;

		q = list_first_entry(&e->queue_list,
				     struct kdbus_name_queue_item,
				     entry_entry);
		kdbus_name_add_to_conn(e, q->conn);
		e->flags = q->flags;
		kdbus_name_queue_item_free(q);
		ret = kdbus_name_send_name_changed_msg(old_conn, e->conn, e);
	}

	return ret;
}

void kdbus_name_remove_by_conn(struct kdbus_name_registry *reg,
			       struct kdbus_conn *conn)
{
	struct kdbus_name_entry *e_tmp, *e;
	struct kdbus_name_queue_item *q_tmp, *q;

	mutex_lock(&reg->entries_lock);

	list_for_each_entry_safe(q, q_tmp, &conn->names_queue_list, conn_entry)
		kdbus_name_queue_item_free(q);

	list_for_each_entry_safe(e, e_tmp, &conn->names_list, conn_entry)
		kdbus_name_entry_release(e);

	mutex_unlock(&reg->entries_lock);
}

struct kdbus_name_entry *kdbus_name_lookup(struct kdbus_name_registry *reg,
					   const char *name, u64 flags)
{
	struct kdbus_name_entry *e = NULL;
	u64 hash = kdbus_name_make_hash(name);

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
	if ((*flags   & KDBUS_CMD_NAME_REPLACE_EXISTING) &&
	    (e->flags & KDBUS_CMD_NAME_ALLOW_REPLACEMENT)) {
		/* ... */
		return kdbus_name_send_name_changed_msg(e->conn, conn, e);
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

/* IOCTL interface */

int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       void __user *buf)
{
	struct kdbus_name_entry *e = NULL;
	struct kdbus_cmd_name *name;
	u64 size;
	u32 hash;
	int ret = 0;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_name, size))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_name)||
	    size > sizeof(struct kdbus_cmd_name) + 256)
		return -EMSGSIZE;

	name = memdup_user(buf, size);
	if (IS_ERR(name))
		return PTR_ERR(name);

	name->flags &= ~KDBUS_CMD_NAME_IN_QUEUE;
	hash = kdbus_name_make_hash(name->name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, name->name);
	if (e) {
		if (e->conn == conn) {
			/* just update flags */
			e->flags = name->flags;
		} else {
			ret = kdbus_name_handle_conflict(reg, conn, e,
							 &name->flags);
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

	e->name = kstrdup(name->name, GFP_KERNEL);
	if (!e->name) {
		ret = -ENOMEM;
		goto err_unlock_free;
	}

	e->flags = name->flags;
	INIT_LIST_HEAD(&e->queue_list);
	INIT_LIST_HEAD(&e->conn_entry);

	hash_add(reg->entries_hash, &e->hentry, hash);
	kdbus_name_add_to_conn(e, conn);

exit_copy:
	ret = copy_to_user(buf, name, size);
	if (ret < 0) {
		ret = -EFAULT;
		goto err_unlock_free;
	}

	kfree(name);
	mutex_unlock(&reg->entries_lock);
	return 0;

err_unlock_free:
	kfree(name);
	kdbus_name_entry_release(e);

err_unlock:
	mutex_unlock(&reg->entries_lock);

	return ret;
}

int kdbus_name_release(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       void __user *buf)
{
	struct kdbus_name_entry *e;
	struct kdbus_cmd_name *name;
	u64 size;
	u32 hash;
	int ret = 0;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_name, size))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_name)||
	    size > sizeof(struct kdbus_cmd_name) + 256)
		return -EMSGSIZE;

	name = memdup_user(buf, size);
	if (IS_ERR(name))
		return PTR_ERR(name);

	hash = kdbus_name_make_hash(name->name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, name->name);
	if (e && e->conn == conn)
		kdbus_name_entry_release(e);
	mutex_unlock(&reg->entries_lock);

	kfree(name);

	return ret;
}

int kdbus_name_list(struct kdbus_name_registry *reg,
		    struct kdbus_conn *conn,
		    void __user *buf)
{
	struct kdbus_cmd_names *names;
	struct kdbus_cmd_name *name;
	struct kdbus_name_entry *e;
	u64 user_size, size = 0, tmp;
	int ret = 0;

	if (kdbus_size_user(user_size, buf, struct kdbus_cmd_names, size))
		return -EFAULT;

	mutex_lock(&reg->entries_lock);

	size = sizeof(struct kdbus_cmd_names);

	hash_for_each(reg->entries_hash, tmp, e, hentry)
		size += sizeof(struct kdbus_cmd_name) + strlen(e->name) + 1;

	if (size > user_size) {
		ret = -ENOSPC;
		goto exit_unlock;
	}

	names = kzalloc(size, GFP_KERNEL);
	if (!names) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	names->size = size;
	name = names->names;

	hash_for_each(reg->entries_hash, tmp, e, hentry) {
		name->size = sizeof(struct kdbus_cmd_name) + strlen(e->name) + 1;
		name->flags = 0; /* FIXME */
		name->id = e->conn->id;
		strcpy(name->name, e->name);
		name = (struct kdbus_cmd_name *) ((u8 *) name + name->size);
	}

	if (copy_to_user(buf, names, size) < 0) {
		ret = -EFAULT;
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&reg->entries_lock);

	return ret;
}

int kdbus_name_query(struct kdbus_name_registry *reg,
		     struct kdbus_conn *conn,
		     void __user *buf)
{
	//struct kdbus_name_entry *e;
	//struct kdbus_cmd_name_info name_info;

	return -ENOSYS;
}
