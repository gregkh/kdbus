/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "item.h"
#include "names.h"
#include "policy.h"

#define KDBUS_POLICY_HASH_SIZE	64

/**
 * struct kdbus_policy_db_entry_access - a database entry access item
 * @type:		One of KDBUS_POLICY_ACCESS_* types
 * @access:		Access to grant. One of KDBUS_POLICY_*
 * @uid:		For KDBUS_POLICY_ACCESS_USER, the global uid
 * @gid:		For KDBUS_POLICY_ACCESS_GROUP, the global gid
 * @list:		List entry item for the entry's list
 *
 * This is the internal version of struct kdbus_policy_db_access.
 */
struct kdbus_policy_db_entry_access {
	u8 type;		/* USER, GROUP, WORLD */
	u8 access;		/* OWN, TALK, SEE */
	union {
		kuid_t uid;	/* global uid */
		kgid_t gid;	/* global gid */
	};
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
 * @wildcard:		The name is a wildcard, such as ending on '.*'
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

static unsigned int kdbus_strnhash(const char *str, size_t len)
{
	unsigned long hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(*str++, hash);

	return end_name_hash(hash);
}

static const struct kdbus_policy_db_entry *
kdbus_policy_lookup(struct kdbus_policy_db *db, const char *name, u32 hash)
{
	struct kdbus_policy_db_entry *e;
	const char *dot;
	size_t len;

	/* find exact match */
	hash_for_each_possible(db->entries_hash, e, hentry, hash)
		if (strcmp(e->name, name) == 0 && !e->wildcard)
			return e;

	/* find wildcard match */

	dot = strrchr(name, '.');
	if (!dot)
		return NULL;

	len = dot - name;
	hash = kdbus_strnhash(name, len);

	hash_for_each_possible(db->entries_hash, e, hentry, hash)
		if (e->wildcard && !strncmp(e->name, name, len) &&
		    !e->name[len])
			return e;

	return NULL;
}

/**
 * kdbus_policy_db_clear - release all memory from a policy db
 * @db:		The policy database
 */
void kdbus_policy_db_clear(struct kdbus_policy_db *db)
{
	struct kdbus_policy_db_entry *e;
	struct hlist_node *tmp;
	unsigned int i;

	/* purge entries */
	down_write(&db->entries_rwlock);
	hash_for_each_safe(db->entries_hash, i, tmp, e, hentry) {
		hash_del(&e->hentry);
		kdbus_policy_entry_free(e);
	}
	up_write(&db->entries_rwlock);
}

/**
 * kdbus_policy_db_init() - initialize a new policy database
 * @db:		The location of the database
 *
 * This initializes a new policy-db. The underlying memory must have been
 * cleared to zero by the caller.
 */
void kdbus_policy_db_init(struct kdbus_policy_db *db)
{
	hash_init(db->entries_hash);
	init_rwsem(&db->entries_rwlock);
}

/**
 * kdbus_policy_query_unlocked() - Query the policy database
 * @db:		Policy database
 * @cred:	Credentials to test against
 * @name:	Name to query
 * @hash:	Hash value of @name
 *
 * Same as kdbus_policy_query() but requires the caller to lock the policy
 * database against concurrent writes.
 *
 * Return: The highest KDBUS_POLICY_* access type found, or -EPERM if none.
 */
int kdbus_policy_query_unlocked(struct kdbus_policy_db *db,
				const struct cred *cred, const char *name,
				unsigned int hash)
{
	struct kdbus_policy_db_entry_access *a;
	const struct kdbus_policy_db_entry *e;
	int i, highest = -EPERM;

	e = kdbus_policy_lookup(db, name, hash);
	if (!e)
		return -EPERM;

	list_for_each_entry(a, &e->access_list, list) {
		if ((int)a->access <= highest)
			continue;

		switch (a->type) {
		case KDBUS_POLICY_ACCESS_USER:
			if (uid_eq(cred->euid, a->uid))
				highest = a->access;
			break;
		case KDBUS_POLICY_ACCESS_GROUP:
			if (gid_eq(cred->egid, a->gid)) {
				highest = a->access;
				break;
			}

			for (i = 0; i < cred->group_info->ngroups; i++) {
				kgid_t gid = GROUP_AT(cred->group_info, i);

				if (gid_eq(gid, a->gid)) {
					highest = a->access;
					break;
				}
			}

			break;
		case KDBUS_POLICY_ACCESS_WORLD:
			highest = a->access;
			break;
		}

		/* OWN is the highest possible policy */
		if (highest >= KDBUS_POLICY_OWN)
			break;
	}

	return highest;
}

/**
 * kdbus_policy_query() - Query the policy database
 * @db:		Policy database
 * @cred:	Credentials to test against
 * @name:	Name to query
 * @hash:	Hash value of @name
 *
 * Query the policy database @db for the access rights of @cred to the name
 * @name. The access rights of @cred are returned, or -EPERM if no access is
 * granted.
 *
 * This call effectively searches for the highest access-right granted to
 * @cred. The caller should really cache those as policy lookups are rather
 * expensive.
 *
 * Return: The highest KDBUS_POLICY_* access type found, or -EPERM if none.
 */
int kdbus_policy_query(struct kdbus_policy_db *db, const struct cred *cred,
		       const char *name, unsigned int hash)
{
	int ret;

	down_read(&db->entries_rwlock);
	ret = kdbus_policy_query_unlocked(db, cred, name, hash);
	up_read(&db->entries_rwlock);

	return ret;
}

static void __kdbus_policy_remove_owner(struct kdbus_policy_db *db,
					const void *owner)
{
	struct kdbus_policy_db_entry *e;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(db->entries_hash, i, tmp, e, hentry)
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
	down_write(&db->entries_rwlock);
	__kdbus_policy_remove_owner(db, owner);
	up_write(&db->entries_rwlock);
}

/*
 * Convert user provided policy access to internal kdbus policy
 * access
 */
static struct kdbus_policy_db_entry_access *
kdbus_policy_make_access(const struct kdbus_policy_access *uaccess)
{
	int ret;
	struct kdbus_policy_db_entry_access *a;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return ERR_PTR(-ENOMEM);

	ret = -EINVAL;
	switch (uaccess->access) {
	case KDBUS_POLICY_SEE:
	case KDBUS_POLICY_TALK:
	case KDBUS_POLICY_OWN:
		a->access = uaccess->access;
		break;
	default:
		goto err;
	}

	switch (uaccess->type) {
	case KDBUS_POLICY_ACCESS_USER:
		a->uid = make_kuid(current_user_ns(), uaccess->id);
		if (!uid_valid(a->uid))
			goto err;

		break;
	case KDBUS_POLICY_ACCESS_GROUP:
		a->gid = make_kgid(current_user_ns(), uaccess->id);
		if (!gid_valid(a->gid))
			goto err;

		break;
	case KDBUS_POLICY_ACCESS_WORLD:
		break;
	default:
		goto err;
	}

	a->type = uaccess->type;

	return a;

err:
	kfree(a);
	return ERR_PTR(ret);
}

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
 * Callers to this function must make sur that the owner is a custom
 * endpoint, or if the endpoint is a default endpoint, then it must be
 * either a policy holder or an activator.
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
	struct kdbus_policy_db_entry_access *a;
	struct kdbus_policy_db_entry *e, *p;
	const struct kdbus_item *item;
	struct hlist_node *tmp;
	HLIST_HEAD(entries);
	HLIST_HEAD(restore);
	size_t count = 0;
	int i, ret = 0;
	u32 hash;

	/* Walk the list of items and look for new policies */
	e = NULL;
	KDBUS_ITEMS_FOREACH(item, items, items_size) {
		switch (item->type) {
		case KDBUS_ITEM_NAME: {
			size_t len;

			if (max_policies && ++count > max_policies) {
				ret = -E2BIG;
				goto exit;
			}

			if (!kdbus_name_is_valid(item->str, true)) {
				ret = -EINVAL;
				goto exit;
			}

			e = kzalloc(sizeof(*e), GFP_KERNEL);
			if (!e) {
				ret = -ENOMEM;
				goto exit;
			}

			INIT_LIST_HEAD(&e->access_list);
			e->owner = owner;
			hlist_add_head(&e->hentry, &entries);

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

			a = kdbus_policy_make_access(&item->policy_access);
			if (IS_ERR(a)) {
				ret = PTR_ERR(a);
				goto exit;
			}

			list_add_tail(&a->list, &e->access_list);
			break;
		}
	}

	down_write(&db->entries_rwlock);

	/* remember previous entries to restore in case of failure */
	hash_for_each_safe(db->entries_hash, i, tmp, e, hentry)
		if (e->owner == owner) {
			hash_del(&e->hentry);
			hlist_add_head(&e->hentry, &restore);
		}

	hlist_for_each_entry_safe(e, tmp, &entries, hentry) {
		/* prevent duplicates */
		hash = kdbus_strhash(e->name);
		hash_for_each_possible(db->entries_hash, p, hentry, hash)
			if (strcmp(e->name, p->name) == 0 &&
			    e->wildcard == p->wildcard) {
				ret = -EEXIST;
				goto restore;
			}

		hlist_del(&e->hentry);
		hash_add(db->entries_hash, &e->hentry, hash);
	}

restore:
	/* if we failed, flush all entries we added so far */
	if (ret < 0)
		__kdbus_policy_remove_owner(db, owner);

	/* if we failed, restore entries, otherwise release them */
	hlist_for_each_entry_safe(e, tmp, &restore, hentry) {
		hlist_del(&e->hentry);
		if (ret < 0) {
			hash = kdbus_strhash(e->name);
			hash_add(db->entries_hash, &e->hentry, hash);
		} else {
			kdbus_policy_entry_free(e);
		}
	}

	up_write(&db->entries_rwlock);

exit:
	hlist_for_each_entry_safe(e, tmp, &entries, hentry) {
		hlist_del(&e->hentry);
		kdbus_policy_entry_free(e);
	}

	return ret;
}
