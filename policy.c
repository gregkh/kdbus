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

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "names.h"
#include "policy.h"

#define KDBUS_POLICY_HASH_SIZE	64

/**
 * struct kdbus_policy_db_cache_entry - a cached entry
 * @conn_a:		Connection A
 * @conn_b:		Connection B
 * @hentry:		The hash table entry for the database's entries_hash
 */
struct kdbus_policy_db_cache_entry {
	struct kdbus_conn *conn_a;
	struct kdbus_conn *conn_b;
	struct hlist_node hentry;
};

/**
 * struct kdbus_policy_db_entry_access - a database entry access item
 * @type:		One of KDBUS_POLICY_ACCESS_* types
 * @access:		Access to grant. One of KDBUS_POLICY_*
 * @id:			For KDBUS_POLICY_ACCESS_USER, the uid
 *			For KDBUS_POLICY_ACCESS_GROUP, the gid
 * @list:		List entry item for the entry's list
 *
 * This is the internal version of struct kdbus_policy_db_access.
 */
struct kdbus_policy_db_entry_access {
	u8 type;	/* USER, GROUP, WORLD */
	u8 access;	/* OWN, TALK, SEE */
	u64 id;		/* uid, gid, 0 */
	struct list_head list;
};

/**
 * struct kdbus_policy_db_entry - a policy database entry
 * @name:		The name to match the policy entry against
 * @hentry:		The hash entry for the database's entries_hash
 * @access_list:	List head for keeping tracks of the entry's
 *			access items.
 * @owner:		The owner of this entry. Can be a kdbus_conn or
 *			a kdbus_ep object.
 */
struct kdbus_policy_db_entry {
	char *name;
	struct hlist_node hentry;
	struct list_head access_list;
	const void *owner;
	bool wildcard:1;
};

static void kdbus_policy_entry_free(struct kdbus_policy_db_entry *e)
{
	struct kdbus_policy_db_entry_access *a, *tmp;

	list_for_each_entry_safe(a, tmp, &e->access_list, list) {
		list_del(&a->list);
		kfree(a);
	}

	kfree(e->name);
	kfree(e);
}

static const struct kdbus_policy_db_entry *
__kdbus_policy_lookup(struct kdbus_policy_db *db,
		      const char *name, u32 hash,
		      bool wildcard)
{
	struct kdbus_policy_db_entry *e, *found = NULL;

	hash_for_each_possible(db->entries_hash, e, hentry, hash)
		if (strcmp(e->name, name) == 0 && !e->wildcard)
			return e;

	if (wildcard) {
		const char *tmp;
		char *dot;

		tmp = kstrdup(name, GFP_KERNEL);
		if (!tmp)
			return NULL;

		dot = strrchr(tmp, '.');
		if (!dot)
			goto exit_free;

		*dot = '\0';
		hash = kdbus_str_hash(tmp);

		hash_for_each_possible(db->entries_hash, e, hentry, hash)
			if (strcmp(e->name, tmp) == 0 && e->wildcard) {
				found = e;
				break;
			}

exit_free:
		kfree(tmp);
	}

	return found;
}

/**
 * kdbus_policy_free - drop a policy database reference
 * @db:		The policy database
 */
void kdbus_policy_db_free(struct kdbus_policy_db *db)
{
	struct kdbus_policy_db_cache_entry *ce;
	struct kdbus_policy_db_entry *e;
	struct hlist_node *tmp;
	unsigned int i;

	if (!db)
		return;

	/* purge entries */
	mutex_lock(&db->entries_lock);
	hash_for_each_safe(db->entries_hash, i, tmp, e, hentry) {
		hash_del(&e->hentry);
		kdbus_policy_entry_free(e);
	}
	mutex_unlock(&db->entries_lock);

	/* purge cache */
	mutex_lock(&db->cache_lock);
	hash_for_each_safe(db->send_access_hash, i, tmp, ce, hentry) {
		hash_del(&ce->hentry);
		kfree(ce);
	}
	mutex_unlock(&db->cache_lock);

	kfree(db);
}

/**
 * kdbus_policy_new() - create a new policy database
 * @db:		The location where to store the new database
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_policy_db_new(struct kdbus_policy_db **db)
{
	struct kdbus_policy_db *d;

	BUG_ON(*db);

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	hash_init(d->entries_hash);
	hash_init(d->send_access_hash);
	mutex_init(&d->entries_lock);
	mutex_init(&d->cache_lock);

	*db = d;

	return 0;
}

void kdbus_policy_db_dump(struct kdbus_policy_db *db)
{
	struct kdbus_policy_db_entry *e;
	int i;

	mutex_lock(&db->entries_lock);
	printk(KERN_INFO "------------[ policy db dump ]--------------\n");

	hash_for_each(db->entries_hash, i, e, hentry) {
		struct kdbus_policy_db_entry_access *a;

		printk(KERN_INFO "name: %s%s, owner %p\n",
			e->name, e->wildcard ? ".* (wildcard)" : "", e->owner);

		list_for_each_entry(a, &e->access_list, list) {
			printk(KERN_INFO "  * ");

			if (a->type == KDBUS_POLICY_ACCESS_USER)
				printk(KERN_CONT "uid %lld", a->id);
			else if (a->type == KDBUS_POLICY_ACCESS_GROUP)
				printk(KERN_CONT "gid %lld", a->id);
			else if (a->type == KDBUS_POLICY_ACCESS_WORLD)
				printk(KERN_CONT "world");

			printk(KERN_CONT " can %s\n",
				(a->access== KDBUS_POLICY_OWN) ? "own" :
				(a->access == KDBUS_POLICY_TALK) ? "talk" :
				(a->access == KDBUS_POLICY_SEE) ? "see" : "");
		}
	}

	printk(KERN_INFO "------------[ END ]--------------\n");
	mutex_unlock(&db->entries_lock);
}

static int kdbus_policy_check_access(const struct kdbus_policy_db_entry *e,
				     const struct cred *cred,
				     unsigned int access)
{
	struct kdbus_policy_db_entry_access *a;
	struct group_info *group_info;
	struct user_namespace *ns;
	uid_t uid;
	int i;

	if (!e)
		return -EPERM;

	ns = cred->user_ns;
	group_info = cred->group_info;
	uid = from_kuid(ns, cred->uid);

	list_for_each_entry(a, &e->access_list, list) {
		if (a->access >= access) {
			switch (a->type) {
			case KDBUS_POLICY_ACCESS_USER:
				if (a->id == uid)
					return 0;
				break;
			case KDBUS_POLICY_ACCESS_GROUP:
				for (i = 0; i < group_info->ngroups; i++) {
					kgid_t gid = GROUP_AT(group_info, i);
					if (a->id == from_kgid_munged(ns, gid))
						return 0;
				}
				break;
			case KDBUS_POLICY_ACCESS_WORLD:
				return 0;
			}
		}
	}

	return -EPERM;
}

/**
 * kdbus_policy_check_own_access() - check whether a connection is allowed
 *				     to own a name
 * @db:		The policy database
 * @conn:	The connection to check
 * @name:	The name to check
 *
 * Return: t0 if the connection is allowed to own the name, -EPERM otherwise
 */
int kdbus_policy_check_own_access(struct kdbus_policy_db *db,
				  const struct kdbus_conn *conn,
				  const char *name)
{
	const struct kdbus_policy_db_entry *e;
	int ret;

	if (kdbus_bus_uid_is_privileged(conn->bus))
		return 0;

	mutex_lock(&db->entries_lock);
	e = __kdbus_policy_lookup(db, name, kdbus_str_hash(name), true);
	ret = kdbus_policy_check_access(e, conn->cred, KDBUS_POLICY_OWN);
	mutex_unlock(&db->entries_lock);

	return ret;
}

static int __kdbus_policy_check_talk_access(struct kdbus_policy_db *db,
					    struct kdbus_conn *conn_dst)
{
	const struct kdbus_policy_db_entry *e;
	struct kdbus_name_entry *name_entry;
	int ret = -EPERM;

	mutex_lock(&conn_dst->lock);
	list_for_each_entry(name_entry, &conn_dst->names_list, conn_entry) {
		u32 hash = kdbus_str_hash(name_entry->name);
		e = __kdbus_policy_lookup(db, name_entry->name, hash, true);
		if (kdbus_policy_check_access(e, current_cred(),
					      KDBUS_POLICY_TALK) == 0) {
			ret = 0;
			break;
		}
	}
	mutex_unlock(&conn_dst->lock);

	return ret;
}

static struct kdbus_policy_db_cache_entry *
kdbus_policy_cache_entry_new(struct kdbus_conn *conn_a,
			     struct kdbus_conn *conn_b)
{
	struct kdbus_policy_db_cache_entry *ce;

	ce = kmalloc(sizeof(*ce), GFP_KERNEL);
	if (!ce)
		return NULL;

	ce->conn_a = conn_a;
	ce->conn_b = conn_b;
	INIT_HLIST_NODE(&ce->hentry);

	return ce;
}

/**
 * kdbus_policy_check_send_access() - check if one connection is allowed
 *				       to send a message to another connection
 * @db:			The policy database
 * @conn_src:		The source connection
 * @conn_dst:		The destination connection
 *
 * Return: 0 if access is granted, -EPERM if not, negative errno on failure
 */
int kdbus_policy_check_talk_access(struct kdbus_policy_db *db,
				   struct kdbus_conn *conn_src,
				   struct kdbus_conn *conn_dst)
{
	struct kdbus_policy_db_cache_entry *ce;
	unsigned int hash = 0;
	int ret;

	if (uid_eq(conn_src->user->uid, conn_dst->user->uid))
		return true;

	/*
	 * If there was a positive match for these two connections before,
	 * there's an entry in the hash table for them.
	 */
	hash ^= hash_ptr(conn_src, KDBUS_POLICY_HASH_SIZE);
	hash ^= hash_ptr(conn_dst, KDBUS_POLICY_HASH_SIZE);

	mutex_lock(&db->cache_lock);
	hash_for_each_possible(db->send_access_hash, ce, hentry, hash)
		if (ce->conn_a == conn_src && ce->conn_b == conn_dst) {
			mutex_unlock(&db->cache_lock);
			return 0;
		}
	mutex_unlock(&db->cache_lock);

	/*
	 * Otherwise, walk the connection list and store and add
	 * a hash table entry if send access is granted.
	 */
	mutex_lock(&db->entries_lock);
	ret = __kdbus_policy_check_talk_access(db, conn_dst);
	if (ret == 0) {
		ce = kdbus_policy_cache_entry_new(conn_src, conn_dst);
		if (!ce) {
			ret = -ENOMEM;
			goto exit_unlock_entries;
		}

		mutex_lock(&db->cache_lock);
		hash_add(db->send_access_hash, &ce->hentry, hash);
		mutex_unlock(&db->cache_lock);
	}

exit_unlock_entries:
	mutex_unlock(&db->entries_lock);

	return ret;
}

/**
 * kdbus_policy_check_see_access() - Check whether the current task is allowed
 * 				     to see a given name
 * @db:		The policy database
 * @name:	The name
 *
 * Return: 0 if permission to see the name is granted, -EPERM otherwise
 */
int kdbus_policy_check_see_access_unlocked(struct kdbus_policy_db *db,
					   const char *name)
{
	const struct kdbus_policy_db_entry *e;

	e = __kdbus_policy_lookup(db, name, kdbus_str_hash(name), true);
	return kdbus_policy_check_access(e, current_cred(), KDBUS_POLICY_SEE);
}

static void __kdbus_policy_remove_owner(struct kdbus_policy_db *db,
					const void *owner)
{
	struct kdbus_policy_db_entry *e;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(db->send_access_hash, i, tmp, e, hentry)
		if (e->owner == owner) {
			hash_del(&e->hentry);
			kdbus_policy_entry_free(e);
		}
}

/**
 * kdbus_policy_remove_owner() - remove all entries related to a connection
 * @db:		The policy database
 * @owner:	The connection which items to remove
 */
void kdbus_policy_remove_owner(struct kdbus_policy_db *db,
			       const void *owner)
{
	mutex_lock(&db->entries_lock);
	__kdbus_policy_remove_owner(db, owner);
	mutex_unlock(&db->entries_lock);
}

/**
 * kdbus_policy_remove_conn() - remove all entries related to a connection
 * @db:		The policy database
 * @conn:	The connection which items to remove
 */
void kdbus_policy_remove_conn(struct kdbus_policy_db *db,
			      const struct kdbus_conn *conn)
{
	struct kdbus_policy_db_cache_entry *ce;
	struct hlist_node *tmp;
	int i;

	mutex_lock(&db->cache_lock);
	hash_for_each_safe(db->send_access_hash, i, tmp, ce, hentry)
		if (ce->conn_a == conn || ce->conn_b == conn) {
			hash_del(&ce->hentry);
			kfree(ce);
		}
	mutex_unlock(&db->cache_lock);
}

static int
kdbus_policy_add_one(struct kdbus_policy_db *db,
		     struct kdbus_policy_db_entry *e)
{
	int ret = 0;
	u32 hash = kdbus_str_hash(e->name);

	if (__kdbus_policy_lookup(db, e->name, hash, false))
		ret = -EEXIST;
	else
		hash_add(db->entries_hash, &e->hentry, hash);

	return ret;
}

/* temporary struct to restore original state */
struct kdbus_policy_list_entry {
	struct kdbus_policy_db_entry *e;
	struct list_head entry;
};

/**
 * kdbus_policy_set() - set a connection's policy rules
 * @db:				The policy database
 * @items:			A list of kdbus_item elements that contain both
 *				names and access rules to set.
 * @items_size:			The total size of the items.
 * @max_policies:		The maximum number of policy entries to allow.
 *				Pass 0 for no limit.
 * @allow_wildcards:		Boolean value whether wildcard entries (such
 *				ending on '.*') should be allowed.
 * @owner:			The owner of the new policy items.
 *
 * This function sets a new set of policies for a given owner. The names and
 * access rules are gathered by walking the list of items passed in as
 * argument. An item of type KDBUS_ITEM_NAME is expected before any number of
 * KDBUS_ITEM_POLICY_ACCESS items. If there are more repetitions of this
 * pattern than denoted in @max_policies, -EINVAL is returned.
 *
 * In order to allow atomic replacement of rules, the function first removes
 * all entries that have been created for the given owner previously.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_policy_set(struct kdbus_policy_db *db,
		     const struct kdbus_item *items,
		     size_t items_size,
		     size_t max_policies,
		     bool allow_wildcards,
		     const void *owner)
{
	struct kdbus_policy_db_entry *e = NULL;
	struct kdbus_policy_db_entry_access *a;
	const struct kdbus_item *item;
	struct hlist_node *tmp;
	size_t count = 0;
	LIST_HEAD(list);
	int i, ret = 0;

	mutex_lock(&db->entries_lock);

	/*
	 * First, walk the list of entries and move those of the
	 * same owner into a temporary list. In case we fail to parse
	 * the new content, we will restore them later.
	 * At the same time, the lookup mechanism won't find any collisions
	 * when looking for already exising names.
	 */
	hash_for_each_safe(db->send_access_hash, i, tmp, e, hentry)
		if (e->owner == owner) {
			struct kdbus_policy_list_entry *l;

			l = kzalloc(sizeof(*l), GFP_KERNEL);
			if (!l) {
				ret = -ENOMEM;
				goto exit;
			}

			l->e = e;
			list_add_tail(&l->entry, &list);
			hash_del(&e->hentry);
		}

	/* Walk the list of items and look for new policies */
	KDBUS_ITEMS_FOREACH(item, items, items_size) {
		if (!KDBUS_ITEM_VALID(item, &items, items_size)) {
			ret = -EINVAL;
			goto exit;
		}

		switch (item->type) {
		case KDBUS_ITEM_NAME: {
			size_t len;

			if (e) {
				ret = kdbus_policy_add_one(db, e);
				if (ret < 0) {
					kdbus_policy_entry_free(e);
					goto exit;
				}
			}

			if (max_policies && ++count > max_policies) {
				ret = -E2BIG;
				goto exit;
			}

			e = kzalloc(sizeof(*e), GFP_KERNEL);
			if (!e) {
				ret = -ENOMEM;
				goto exit;
			}

			INIT_LIST_HEAD(&e->access_list);
			e->owner = owner;

			e->name = kstrdup(item->str, GFP_KERNEL);
			if (!e->name) {
				ret = -ENOMEM;
				goto exit;
			}

			/*
			 * If a supplied name ends with an '.*', cut off that
			 * part, only store anything before it, and mark the
			 * entry as wildcard.
			 */
			len = strlen(e->name);
			if (len > 2 &&
			    e->name[len - 3] == '.' &&
			    e->name[len - 2] == '*') {
				if (!allow_wildcards) {
					ret = -EINVAL;
					goto exit;
				}

				e->name[len - 3] = '\0';
				e->wildcard = true;
			}

			break;
		}

		case KDBUS_ITEM_POLICY_ACCESS:
			if (!e) {
				ret = -EINVAL;
				goto exit;
			}

			a = kzalloc(sizeof(*a), GFP_KERNEL);
			if (!a) {
				ret = -ENOMEM;
				goto exit;
			}

			a->type = item->policy_access.type;
			a->access = item->policy_access.access;
			a->id   = item->policy_access.id;
			list_add_tail(&a->list, &e->access_list);
			break;
		}
	}

	if (!KDBUS_ITEMS_END(item, items, items_size))
		return -EINVAL;

	if (e) {
		ret = kdbus_policy_add_one(db, e);
		if (ret < 0)
			kdbus_policy_entry_free(e);
	}

exit:
	if (ret < 0) {
		struct kdbus_policy_list_entry *l, *l_tmp;

		if (e)
			kdbus_policy_entry_free(e);

		/* purge any entries that might have been added above */
		__kdbus_policy_remove_owner(db, owner);

		/* restore original entries from list */
		list_for_each_entry_safe(l, l_tmp, &list, entry) {
			kdbus_policy_add_one(db, e);
			kfree(l);
		}
	}

	mutex_unlock(&db->entries_lock);

	return ret;
}
