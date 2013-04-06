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
#include <linux/poll.h>
#include "kdbus.h"

#include "kdbus_internal.h"

struct kdbus_policy_db_entry_access {
	__u32			type;	/* USER, GROUP, WORLD */
	__u32			bits;	/* RECV, SEND, OWN */
	__u64			id;	/* uid, gid, 0 */
	struct list_head	list;
};

struct kdbus_policy_db_entry {
	char			*name;
	struct hlist_node	hentry;
	struct list_head	access_list;
};

static void __kdbus_policy_db_free(struct kref *kref)
{
	struct kdbus_policy_db_entry *e;
	struct hlist_node *tmp;
	struct kdbus_policy_db *db =
		container_of(kref, struct kdbus_policy_db, kref);
	int i;

	mutex_lock(&db->entries_lock);
	hash_for_each_safe(db->entries_hash, i, tmp, e, hentry) {
		struct kdbus_policy_db_entry_access *a, *tmp;

		list_for_each_entry_safe(a, tmp, &e->access_list, list) {
			list_del(&a->list);
			kfree(a);
		}

		hash_del(&e->hentry);
		kfree(e->name);
		kfree(e);
	}
	mutex_unlock(&db->entries_lock);

	kfree(db);
}

void kdbus_policy_db_unref(struct kdbus_policy_db *db)
{
	kref_put(&db->kref, __kdbus_policy_db_free);
}

static u32 kdbus_policy_make_name_hash(const char *name)
{
	unsigned int len = strlen(name);
	u32 hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(*name++, hash);

	return end_name_hash(hash);
}

struct kdbus_policy_db *kdbus_policy_db_new(void)
{
	struct kdbus_policy_db *db;

	db = kzalloc(sizeof(*db), GFP_KERNEL);
	if (!db)
		return NULL;

	kref_init(&db->kref);
	hash_init(db->entries_hash);
	mutex_init(&db->entries_lock);


	return db;
}

static inline
u64 accumulate_entry_accesses(struct kdbus_policy_db_entry *db_entry,
			      struct kdbus_conn *conn)
{
	struct kdbus_policy_db_entry_access *a;
	u64 access = 0;

	list_for_each_entry(a, &db_entry->access_list, list) {
		switch (a->type) {
		case KDBUS_POLICY_USER:
			if (conn->creds.uid == a->id)
				access |= a->bits;
			break;
		case KDBUS_POLICY_GROUP:
			if (conn->creds.gid == a->id)
				access |= a->bits;
			break;
		case KDBUS_POLICY_WORLD:
			access |= a->bits;
			break;
		}
	}

	return access;
}

static
int kdbus_policy_db_check_access(struct kdbus_policy_db *db,
				 struct kdbus_conn *conn,
				 u64 bits)
{
	struct kdbus_name_entry *name_entry;
	int ret = -EPERM;

	/* Walk the list of the names registered for a connection ... */
	mutex_lock(&db->entries_lock);
	list_for_each_entry(name_entry, &conn->names_list, conn_entry) {
		struct kdbus_policy_db_entry *db_entry;
		u32 hash = kdbus_policy_make_name_hash(name_entry->name);
		/* ... and check each entry of our policy db that matches 
		 * that name */
		hash_for_each_possible(db->entries_hash, db_entry,
				       hentry, hash) {
			u64 access;

			if (strcmp(db_entry->name, name_entry->name) != 0)
				continue;

			/* test whether the policy entry has an access entry
			 * that fullfills the permission bits we're looking
			 * for, and bail out if it does */
			access = accumulate_entry_accesses(db_entry, conn);
			if (access & bits) {
				ret = 0;
				goto exit_unlock;
			}
		}
	}

exit_unlock:
	mutex_unlock(&db->entries_lock);

	return ret;
}

int kdbus_policy_db_check_send_access(struct kdbus_policy_db *db,
				      struct kdbus_conn *conn_src,
				      struct kdbus_conn *conn_dst)
{
	u64 access;

	if (conn_src->ep != conn_dst->ep)
		return -EINVAL;

	/* send access is granted if either the source connection has a
	 * matching SEND rule ...*/
	access = kdbus_policy_db_check_access(db, conn_src, KDBUS_POLICY_SEND);
	if (access == 0)
		return 0;

	/* ... or the receiver connection has a matching RECV rule. */
	access = kdbus_policy_db_check_access(db, conn_dst, KDBUS_POLICY_RECV);
	if (access == 0)
		return 0;

	return -EPERM;
}

int kdbus_policy_db_check_own_access(struct kdbus_policy_db *db,
				     struct kdbus_conn *conn)
{
	return kdbus_policy_db_check_access(db, conn, KDBUS_POLICY_OWN);
}

static int kdbus_policy_db_add_one(struct kdbus_policy_db *db,
				   const struct kdbus_policy *pol)
{
	struct kdbus_policy_db_entry *current_entry = NULL;

	switch (pol->type) {
	case KDBUS_POLICY_NAME: {
		struct kdbus_policy_db_entry *e;
		u32 hash;

		e = kzalloc(sizeof(*e), GFP_KERNEL);
		if (!e)
			return -ENOMEM;

		hash = kdbus_policy_make_name_hash(pol->name);
		e->name = kstrdup(pol->name, GFP_KERNEL);
		INIT_LIST_HEAD(&e->access_list);

		mutex_lock(&db->entries_lock);
		hash_add(db->entries_hash, &e->hentry, hash);
		mutex_unlock(&db->entries_lock);

		current_entry = e;
		break;
	}
	case KDBUS_POLICY_ACCESS: {
		struct kdbus_policy_db_entry_access *a;

		if (!current_entry)
			return -EINVAL;

		a = kzalloc(sizeof(*a), GFP_KERNEL);
		if (!a)
			return -ENOMEM;

		a->type = pol->access.type;
		a->bits = pol->access.bits;
		a->id   = pol->access.id;
		INIT_LIST_HEAD(&a->list);

		mutex_lock(&db->entries_lock);
		list_add_tail(&a->list, &current_entry->access_list);
		mutex_unlock(&db->entries_lock);

		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}

int kdbus_policy_set_from_user(struct kdbus_policy_db *db,
			       void __user *buf)
{
	struct kdbus_cmd_policy *cmd;
	struct kdbus_policy *pol;
	u64 size;
	int ret;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_policy, size))
		return -EFAULT;

	if (size < sizeof(struct kdbus_msg) || size > 0xffff)
		return -EMSGSIZE;

	cmd = memdup_user(buf, size);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	size -= offsetof(struct kdbus_cmd_policy, buffer);
	pol = (struct kdbus_policy *) cmd->buffer;

	while (size > 0) {
		ret = kdbus_policy_db_add_one(db, pol);
		if (ret < 0)
			break;

		size -= pol->size;
		pol = (struct kdbus_policy *) ((u8 *) pol + pol->size);
	}

	kfree(cmd);

	return 0;
}
