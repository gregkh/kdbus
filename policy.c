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

struct kdbus_policy_db_entry {
	__u64 type; /* NAME or ACCESS */
	union {
		char name[0];
		struct {
			__u32 type;	/* USER, GROUP, WORLD */
			__u32 bits;	/* RECV, SEND, OWN */
			__u64 id;	/* uid, gid, 0 */
		} access;
	};
	struct hlist_node	hentry;
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
		hash_del(&e->hentry);
		kfree(e);
	}
	mutex_unlock(&db->entries_lock);

	kfree(db);
}

void kdbus_policy_db_unref(struct kdbus_policy_db *db)
{
	kref_put(&db->kref, __kdbus_policy_db_free);
}

static u32 kdbus_name_make_name_hash(const char *name)
{
	unsigned int len = strlen(name);
	u32 hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(*name++, hash);

	return end_name_hash(hash);
}

static u32 kdbus_name_make_access_hash(u64 type, u64 bits, u64 id)
{
	u32 hash = init_name_hash();

	hash = partial_name_hash(type, hash);
	hash = partial_name_hash(bits, hash);
	hash = partial_name_hash(id, hash);

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

int kdbus_policy_db_check_access(struct kdbus_policy_db *db,
				 struct kdbus_conn *conn_from,
				 struct kdbus_conn *conn_to,
				 u8 type)
{
	if (conn_from->ep != conn_to->ep)
		return -EINVAL;

	switch (type) {
	case KDBUS_POLICY_RECV:
	case KDBUS_POLICY_SEND:
	case KDBUS_POLICY_OWN:
		break;
	}

	return -EPERM;
}

static int kdbus_policy_db_add_one(struct kdbus_policy_db *db,
				   const struct kdbus_policy *pol)
{
	struct kdbus_policy_db_entry *e;
	int ret = 0;
	u32 hash;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	switch (pol->type) {
	case KDBUS_POLICY_NAME:
		hash = kdbus_name_make_name_hash(pol->name);
		break;
	case KDBUS_POLICY_ACCESS:
		hash = kdbus_name_make_access_hash(pol->access.type,
						   pol->access.bits,
						   pol->access.id);
		break;
	default:
		ret = -EINVAL;
		goto err_free;
	}

	e->access.type = pol->access.type;
	e->access.bits = pol->access.bits;
	e->access.id = pol->access.id;

	hash_add(db->entries_hash, &e->hentry, hash);

	return 0;

err_free:
	kfree(e);
	return ret;
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
	if (!cmd)
		return -EFAULT;

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
