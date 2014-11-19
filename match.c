/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 * Copyright (C) 2014 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "item.h"
#include "match.h"
#include "message.h"

/**
 * struct kdbus_match_db - message filters
 * @entries_list:	List of matches
 * @mdb_rwlock:		Match data lock
 * @entries_count:	Number of entries in database
 */
struct kdbus_match_db {
	struct list_head entries_list;
	struct rw_semaphore mdb_rwlock;
	unsigned int entries_count;
};

/**
 * struct kdbus_match_entry - a match database entry
 * @cookie:		User-supplied cookie to lookup the entry
 * @list_entry:		The list entry element for the db list
 * @rules_list:		The list head for tracking rules of this entry
 */
struct kdbus_match_entry {
	u64 cookie;
	struct list_head list_entry;
	struct list_head rules_list;
};

/**
 * struct kdbus_bloom_mask - mask to match against filter
 * @generations:	Number of generations carried
 * @data:		Array of bloom bit fields
 */
struct kdbus_bloom_mask {
	u64 generations;
	u64 *data;
};

/**
 * struct kdbus_match_rule - a rule appended to a match entry
 * @type:		An item type to match agains
 * @bloom_mask:		Bloom mask to match a message's filter against, used
 *			with KDBUS_ITEM_BLOOM_MASK
 * @name:		Name to match against, used with KDBUS_ITEM_NAME,
 *			KDBUS_ITEM_NAME_{ADD,REMOVE,CHANGE}
 * @old_id:		ID to match against, used with
 *			KDBUS_ITEM_NAME_{ADD,REMOVE,CHANGE},
 *			KDBUS_ITEM_ID_REMOVE
 * @new_id:		ID to match against, used with
 *			KDBUS_ITEM_NAME_{ADD,REMOVE,CHANGE},
 *			KDBUS_ITEM_ID_REMOVE
 * @src_id:		ID to match against, used with KDBUS_ITEM_ID
 * @rules_entry:	Entry in the entry's rules list
 */
struct kdbus_match_rule {
	u64 type;
	union {
		struct kdbus_bloom_mask bloom_mask;
		struct {
			char *name;
			u64 old_id;
			u64 new_id;
		};
		u64 src_id;
	};
	struct list_head rules_entry;
};

static void kdbus_match_rule_free(struct kdbus_match_rule *rule)
{
	switch (rule->type) {
	case KDBUS_ITEM_BLOOM_MASK:
		kfree(rule->bloom_mask.data);
		break;

	case KDBUS_ITEM_NAME:
	case KDBUS_ITEM_NAME_ADD:
	case KDBUS_ITEM_NAME_REMOVE:
	case KDBUS_ITEM_NAME_CHANGE:
		kfree(rule->name);
		break;

	case KDBUS_ITEM_ID:
	case KDBUS_ITEM_ID_ADD:
	case KDBUS_ITEM_ID_REMOVE:
		break;

	default:
		BUG();
	}

	list_del(&rule->rules_entry);
	kfree(rule);
}

static void kdbus_match_entry_free(struct kdbus_match_entry *entry)
{
	struct kdbus_match_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &entry->rules_list, rules_entry)
		kdbus_match_rule_free(r);

	list_del(&entry->list_entry);
	kfree(entry);
}

/**
 * kdbus_match_db_free() - free match db resources
 * @mdb:		The match database
 */
void kdbus_match_db_free(struct kdbus_match_db *mdb)
{
	struct kdbus_match_entry *entry, *tmp;

	down_write(&mdb->mdb_rwlock);
	list_for_each_entry_safe(entry, tmp, &mdb->entries_list, list_entry)
		kdbus_match_entry_free(entry);
	up_write(&mdb->mdb_rwlock);

	kfree(mdb);
}

/**
 * kdbus_match_db_new() - create a new match database
 *
 * Return: a new kdbus_match_db on success, ERR_PTR on failure.
 */
struct kdbus_match_db *kdbus_match_db_new(void)
{
	struct kdbus_match_db *d;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return ERR_PTR(-ENOMEM);

	init_rwsem(&d->mdb_rwlock);
	INIT_LIST_HEAD(&d->entries_list);

	return d;
}

static bool kdbus_match_bloom(const struct kdbus_bloom_filter *filter,
			      const struct kdbus_bloom_mask *mask,
			      const struct kdbus_conn *conn)
{
	size_t n = conn->ep->bus->bloom.size / sizeof(u64);
	const u64 *m;
	size_t i;

	/*
	 * The message's filter carries a generation identifier, the
	 * match's mask possibly carries an array of multiple generations
	 * of the mask. Select the mask with the closest match of the
	 * filter's generation.
	 */
	m = mask->data + (min(filter->generation, mask->generations - 1) * n);

	/*
	 * The message's filter contains the messages properties,
	 * the match's mask contains the properties to look for in the
	 * message. Check the mask bit field against the filter bit field,
	 * if the message possibly carries the properties the connection
	 * has subscribed to.
	 */
	for (i = 0; i < n; i++)
		if ((filter->data[i] & m[i]) != m[i])
			return false;

	return true;
}

static bool kdbus_match_rules(const struct kdbus_match_entry *entry,
			      struct kdbus_conn *conn_src,
			      struct kdbus_kmsg *kmsg)
{
	struct kdbus_match_rule *r;

	/*
	 * Walk all the rules and bail out immediately
	 * if any of them is unsatisfied.
	 */

	list_for_each_entry(r, &entry->rules_list, rules_entry) {
		if (conn_src == NULL) {
			/* kernel notifications */

			if (kmsg->notify_type != r->type)
				return false;

			switch (r->type) {
			case KDBUS_ITEM_ID_ADD:
				if (r->new_id != KDBUS_MATCH_ID_ANY &&
				    r->new_id != kmsg->notify_new_id)
					return false;

				break;

			case KDBUS_ITEM_ID_REMOVE:
				if (r->old_id != KDBUS_MATCH_ID_ANY &&
				    r->old_id != kmsg->notify_old_id)
					return false;

				break;

			case KDBUS_ITEM_NAME_ADD:
			case KDBUS_ITEM_NAME_CHANGE:
			case KDBUS_ITEM_NAME_REMOVE:
				if ((r->old_id != KDBUS_MATCH_ID_ANY &&
				     r->old_id != kmsg->notify_old_id) ||
				    (r->new_id != KDBUS_MATCH_ID_ANY &&
				     r->new_id != kmsg->notify_new_id) ||
				    (r->name && kmsg->notify_name &&
				     strcmp(r->name, kmsg->notify_name) != 0))
					return false;

				break;

			default:
				return false;
			}
		} else {
			/* messages from userspace */

			switch (r->type) {
			case KDBUS_ITEM_BLOOM_MASK:
				if (!kdbus_match_bloom(kmsg->bloom_filter,
						       &r->bloom_mask,
						       conn_src))
					return false;
				break;

			case KDBUS_ITEM_ID:
				if (r->src_id != conn_src->id &&
				    r->src_id != KDBUS_MATCH_ID_ANY)
					return false;

				break;

			case KDBUS_ITEM_NAME:
				if (!kdbus_conn_has_name(conn_src, r->name))
					return false;

				break;

			default:
				return false;
			}
		}
	}

	return true;
}

/**
 * kdbus_match_db_match_kmsg() - match a kmsg object agains the database entries
 * @mdb:		The match database
 * @conn_src:		The connection object originating the message
 * @kmsg:		The kmsg to perform the match on
 *
 * This function will walk through all the database entries previously uploaded
 * with kdbus_match_db_add(). As soon as any of them has an all-satisfied rule
 * set, this function will return true.
 *
 * Return: true if there was a matching database entry, false otherwise.
 */
bool kdbus_match_db_match_kmsg(struct kdbus_match_db *mdb,
			       struct kdbus_conn *conn_src,
			       struct kdbus_kmsg *kmsg)
{
	struct kdbus_match_entry *entry;
	bool matched = false;

	down_read(&mdb->mdb_rwlock);
	list_for_each_entry(entry, &mdb->entries_list, list_entry) {
		matched = kdbus_match_rules(entry, conn_src, kmsg);
		if (matched)
			break;
	}
	up_read(&mdb->mdb_rwlock);

	return matched;
}

static int kdbus_match_db_remove_unlocked(struct kdbus_match_db *mdb,
					  uint64_t cookie)
{
	struct kdbus_match_entry *entry, *tmp;
	bool found = false;

	list_for_each_entry_safe(entry, tmp, &mdb->entries_list, list_entry)
		if (entry->cookie == cookie) {
			kdbus_match_entry_free(entry);
			--mdb->entries_count;
			found = true;
		}

	return found ? 0 : -ENOENT;
}

/**
 * kdbus_match_db_add() - add an entry to the match database
 * @conn:		The connection that was used in the ioctl call
 * @cmd:		The command as provided by the ioctl call
 *
 * This function is used in the context of the KDBUS_CMD_MATCH_ADD ioctl
 * interface.
 *
 * One call to this function (or one ioctl(KDBUS_CMD_MATCH_ADD), respectively,
 * adds one new database entry with n rules attached to it. Each rule is
 * described with an kdbus_item, and an entry is considered matching if all
 * its rules are satisfied.
 *
 * The items attached to a kdbus_cmd_match struct have the following mapping:
 *
 * KDBUS_ITEM_BLOOM_MASK:	A bloom mask
 * KDBUS_ITEM_NAME:		A connection's source name
 * KDBUS_ITEM_ID:		A connection ID
 * KDBUS_ITEM_NAME_ADD:
 * KDBUS_ITEM_NAME_REMOVE:
 * KDBUS_ITEM_NAME_CHANGE:	Well-known name changes, carry
 *				kdbus_notify_name_change
 * KDBUS_ITEM_ID_ADD:
 * KDBUS_ITEM_ID_REMOVE:	Connection ID changes, carry
 *				kdbus_notify_id_change
 *
 * For kdbus_notify_{id,name}_change structs, only the ID and name fields
 * are looked at at when adding an entry. The flags are unused.
 *
 * Also note that KDBUS_ITEM_BLOOM_MASK, KDBUS_ITEM_NAME and KDBUS_ITEM_ID
 * are used to match messages from userspace, while the others apply to
 * kernel-generated notifications.
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_match_db_add(struct kdbus_conn *conn,
		       struct kdbus_cmd_match *cmd)
{
	struct kdbus_match_entry *entry = NULL;
	struct kdbus_match_db *mdb = conn->match_db;
	struct kdbus_item *item;
	int ret = 0;

	lockdep_assert_held(conn);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->cookie = cmd->cookie;
	INIT_LIST_HEAD(&entry->list_entry);
	INIT_LIST_HEAD(&entry->rules_list);

	KDBUS_ITEMS_FOREACH(item, cmd->items, KDBUS_ITEMS_SIZE(cmd, items)) {
		struct kdbus_match_rule *rule;
		size_t size = item->size - offsetof(struct kdbus_item, data);

		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule) {
			ret = -ENOMEM;
			break;
		}

		switch (item->type) {
		/* First matches for userspace messages */
		case KDBUS_ITEM_BLOOM_MASK: {
			u64 bsize = conn->ep->bus->bloom.size;
			u64 generations;
			u64 remainder;

			generations = div64_u64_rem(size, bsize, &remainder);
			if (size < bsize || remainder > 0) {
				ret = -EDOM;
				break;
			}

			rule->bloom_mask.data = kmemdup(item->data,
							size, GFP_KERNEL);
			if (!rule->bloom_mask.data) {
				ret = -ENOMEM;
				break;
			}

			/* we get an array of n generations of bloom masks */
			rule->bloom_mask.generations = generations;

			break;
		}

		case KDBUS_ITEM_NAME:
			/*
			 * Do not allow wildcard for now, since we
			 * must validate the wildcard first
			 */
			if (!kdbus_name_is_valid(item->str, false)) {
				ret = -EINVAL;
				break;
			}

			rule->name = kstrdup(item->str, GFP_KERNEL);
			if (!rule->name)
				ret = -ENOMEM;

			break;

		case KDBUS_ITEM_ID:
			rule->src_id = item->id;
			break;

		/* Now matches for kernel messages */
		case KDBUS_ITEM_NAME_ADD:
		case KDBUS_ITEM_NAME_REMOVE:
		case KDBUS_ITEM_NAME_CHANGE: {
			rule->old_id = item->name_change.old_id.id;
			rule->new_id = item->name_change.new_id.id;

			if (size > sizeof(struct kdbus_notify_name_change)) {
				rule->name = kstrdup(item->name_change.name,
						     GFP_KERNEL);
				if (!rule->name)
					ret = -ENOMEM;
			}

			break;
		}

		case KDBUS_ITEM_ID_ADD:
		case KDBUS_ITEM_ID_REMOVE:
			if (item->type == KDBUS_ITEM_ID_ADD)
				rule->new_id = item->id_change.id;
			else
				rule->old_id = item->id_change.id;

			break;

		default:
			ret = -EINVAL;
			break;
		}

		if (ret < 0) {
			kfree(rule);
			break;
		}

		rule->type = item->type;

		list_add_tail(&rule->rules_entry, &entry->rules_list);
	}

	down_write(&mdb->mdb_rwlock);

	/* Remove any entry that has the same cookie as the current one. */
	if (cmd->flags & KDBUS_MATCH_REPLACE)
		kdbus_match_db_remove_unlocked(mdb, entry->cookie);

	/*
	 * If the above removal caught any entry, there will be room for the
	 * new one.
	 */
	if (++mdb->entries_count > KDBUS_MATCH_MAX) {
		--mdb->entries_count;
		ret = -EMFILE;
	}

	if (ret == 0)
		list_add_tail(&entry->list_entry, &mdb->entries_list);
	else
		kdbus_match_entry_free(entry);

	up_write(&mdb->mdb_rwlock);

	return ret;
}

/**
 * kdbus_match_db_remove() - remove an entry from the match database
 * @conn:		The connection that was used in the ioctl call
 * @cmd:		Pointer to the match data structure
 *
 * This function is used in the context of the KDBUS_CMD_MATCH_REMOVE
 * ioctl interface.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_match_db_remove(struct kdbus_conn *conn,
			  struct kdbus_cmd_match *cmd)
{
	struct kdbus_match_db *mdb = conn->match_db;
	int ret;

	lockdep_assert_held(conn);

	down_write(&mdb->mdb_rwlock);
	ret = kdbus_match_db_remove_unlocked(mdb, cmd->cookie);
	up_write(&mdb->mdb_rwlock);

	return ret;
}
