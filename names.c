/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "names.h"
#include "notify.h"
#include "policy.h"

/**
 * struct kdbus_name_queue_item - a queue item for a name
 * @conn:		The associated connection
 * @entry:		Name entry queuing up for
 * @entry_entry:	List element for the list in @entry
 * @conn_entry:		List element for the list in @conn
 * @flags:		The queuing flags
 */
struct kdbus_name_queue_item {
	struct kdbus_conn *conn;
	struct kdbus_name_entry *entry;
	struct list_head entry_entry;
	struct list_head conn_entry;
	u64 flags;
};

static void kdbus_name_entry_free(struct kdbus_name_entry *e)
{
	hash_del(&e->hentry);
	kfree(e->name);
	kfree(e);
}

/**
 * kdbus_name_registry_free() - drop a name reg's reference
 * @reg:		The name registry
 *
 * Cleanup the name registry's internal structures.
 */
void kdbus_name_registry_free(struct kdbus_name_registry *reg)
{
	struct kdbus_name_entry *e;
	struct hlist_node *tmp;
	unsigned int i;

	hash_for_each_safe(reg->entries_hash, i, tmp, e, hentry)
		kdbus_name_entry_free(e);

	kfree(reg);
}

/**
 * kdbus_name_registry_new() - create a new name registry
 * @reg:		The returned name registry
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_name_registry_new(struct kdbus_name_registry **reg)
{
	struct kdbus_name_registry *r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	hash_init(r->entries_hash);
	init_rwsem(&r->rwlock);

	*reg = r;
	return 0;
}

static struct kdbus_name_entry *
kdbus_name_lookup(struct kdbus_name_registry *reg, u32 hash, const char *name)
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

/*
 * The caller needs to hold its own reference, so the connection does not go
 * away while the entry's reference is dropped under lock.
 */
static void kdbus_name_entry_remove_owner(struct kdbus_name_entry *e)
{
	BUG_ON(!e->conn);
	BUG_ON(!mutex_is_locked(&e->conn->lock));

	e->conn->name_count--;
	list_del(&e->conn_entry);
	e->conn = kdbus_conn_unref(e->conn);
}

static void kdbus_name_entry_set_owner(struct kdbus_name_entry *e,
				       struct kdbus_conn *conn)
{
	BUG_ON(e->conn);
	BUG_ON(!mutex_is_locked(&conn->lock));

	e->conn = kdbus_conn_ref(conn);
	list_add_tail(&e->conn_entry, &e->conn->names_list);
	conn->name_count++;
}

static int kdbus_name_replace_owner(struct kdbus_name_entry *e,
				    struct kdbus_conn *conn, u64 flags)
{
	struct kdbus_conn *conn_old = kdbus_conn_ref(e->conn);
	int ret;

	BUG_ON(conn == conn_old);
	BUG_ON(!conn_old);

	/* take lock of both connections in a defined order */
	if (conn < conn_old) {
		mutex_lock(&conn->lock);
		mutex_lock_nested(&conn_old->lock, 1);
	} else {
		mutex_lock(&conn_old->lock);
		mutex_lock_nested(&conn->lock, 1);
	}

	if (!kdbus_conn_active(conn)) {
		ret = -ECONNRESET;
		goto exit_unlock;
	}

	ret = kdbus_notify_name_change(conn->bus, KDBUS_ITEM_NAME_CHANGE,
				       e->conn->id, conn->id,
				       e->flags, flags, e->name);
	if (ret < 0)
		goto exit_unlock;

	/* hand over name ownership */
	kdbus_name_entry_remove_owner(e);
	kdbus_name_entry_set_owner(e, conn);
	e->flags = flags;

exit_unlock:
	mutex_unlock(&conn_old->lock);
	mutex_unlock(&conn->lock);

	kdbus_conn_unref(conn_old);
	return ret;
}

static int kdbus_name_entry_release(struct kdbus_name_entry *e,
				    struct kdbus_bus *bus)
{
	struct kdbus_conn *conn;

	/* give it to first active waiter in the queue */
	while (!list_empty(&e->queue_list)) {
		struct kdbus_name_queue_item *q;
		int ret;

		q = list_first_entry(&e->queue_list,
				     struct kdbus_name_queue_item,
				     entry_entry);

		ret = kdbus_name_replace_owner(e, q->conn, q->flags);
		if (ret < 0)
			continue;

		kdbus_name_queue_item_free(q);
		return 0;
	}

	/* hand it back to an active activator connection */
	if (e->activator && e->activator != e->conn) {
		u64 flags = KDBUS_NAME_ACTIVATOR;
		int ret;

		/*
		 * Move messages still queued in the old connection
		 * and addressed to that name to the new connection.
		 * This allows a race and loss-free name and message
		 * takeover and exit-on-idle services.
		 */
		ret = kdbus_conn_move_messages(e->activator, e->conn,
					       e->name_id);
		if (ret < 0)
			goto exit_release;

		return kdbus_name_replace_owner(e, e->activator, flags);
	}

exit_release:
	/* release the name */
	kdbus_notify_name_change(e->conn->bus, KDBUS_ITEM_NAME_REMOVE,
				 e->conn->id, 0,
				 e->flags, 0, e->name);

	conn = kdbus_conn_ref(e->conn);
	mutex_lock(&conn->lock);
	kdbus_name_entry_remove_owner(e);
	mutex_unlock(&conn->lock);
	kdbus_conn_unref(conn);

	kdbus_conn_unref(e->activator);
	kdbus_name_entry_free(e);

	return 0;
}

static int kdbus_name_release(struct kdbus_name_registry *reg,
			      struct kdbus_conn *conn,
			      const char *name)
{
	struct kdbus_name_queue_item *q_tmp, *q;
	struct kdbus_name_entry *e = NULL;
	u32 hash;
	int ret = 0;

	hash = kdbus_str_hash(name);

	/* lock order: domain -> bus -> ep -> names -> connection */
	mutex_lock(&conn->bus->lock);
	down_write(&reg->rwlock);

	e = kdbus_name_lookup(reg, hash, name);
	if (!e) {
		ret = -ESRCH;
		goto exit_unlock;
	}

	/* Is the connection already the real owner of the name? */
	if (e->conn == conn) {
		ret = kdbus_name_entry_release(e, conn->bus);
	} else {
		/*
		 * Otherwise, walk the list of queued entries and search
		 * for items for connection.
		 */

		/* In case the name belongs to somebody else */
		ret = -EADDRINUSE;

		list_for_each_entry_safe(q, q_tmp,
					 &e->queue_list,
					 entry_entry) {
			if (q->conn != conn)
				continue;

			kdbus_name_queue_item_free(q);
			ret = 0;
			break;
		}
	}

	/*
	 * Now that the connection has lost a name, purge all cached policy
	 * entries, so upon the next message, TALK access will be checked
	 * against the names the connection actually owns.
	 */
	if (ret == 0)
		kdbus_conn_purge_policy_cache(conn);

exit_unlock:
	up_write(&reg->rwlock);
	mutex_unlock(&conn->bus->lock);

	return ret;
}

/**
 * kdbus_name_remove_by_conn() - remove all name entries of a given connection
 * @reg:		The name registry
 * @conn:		The connection which entries to remove
 *
 * This function removes all name entry held by a given connection.
 */
void kdbus_name_remove_by_conn(struct kdbus_name_registry *reg,
			       struct kdbus_conn *conn)
{
	struct kdbus_name_queue_item *q_tmp, *q;
	struct kdbus_conn *activator = NULL;
	struct kdbus_name_entry *e_tmp, *e;
	LIST_HEAD(names_queue_list);
	LIST_HEAD(names_list);

	/* lock order: domain -> bus -> ep -> names -> conn */
	mutex_lock(&conn->bus->lock);
	down_write(&reg->rwlock);

	mutex_lock(&conn->lock);
	list_splice_init(&conn->names_list, &names_list);
	list_splice_init(&conn->names_queue_list, &names_queue_list);
	mutex_unlock(&conn->lock);

	if (kdbus_conn_is_activator(conn)) {
		activator = conn->activator_of->activator;
		conn->activator_of->activator = NULL;
	}
	list_for_each_entry_safe(q, q_tmp, &names_queue_list, conn_entry)
		kdbus_name_queue_item_free(q);
	list_for_each_entry_safe(e, e_tmp, &names_list, conn_entry)
		kdbus_name_entry_release(e, conn->bus);

	up_write(&reg->rwlock);
	mutex_unlock(&conn->bus->lock);

	kdbus_conn_unref(activator);
	kdbus_notify_flush(conn->bus);
}

/**
 * kdbus_name_lock() - look up a name in a name registry and lock it
 * @reg:		The name registry
 * @name:		The name to look up
 *
 * Search for a name in a given name registry and return it with the
 * registry-lock held. If the object is not found, the lock is not acquired and
 * NULL is returned. The caller is responsible of unlocking the name via
 * kdbus_name_unlock() again. Note that kdbus_name_unlock() can be safely called
 * with NULL as name. In this case, it's a no-op as nothing was locked.
 *
 * The *_lock() + *_unlock() logic is only required for callers that need to
 * protect their code against concurrent activator/implementor name changes.
 * Multiple readers can lock names concurrently. However, you may not change
 * name-ownership while holding a name-lock.
 *
 * Return: NULL if name is unknown, otherwise return a pointer to the name
 *         entry with the name-lock held (reader lock only).
 */
struct kdbus_name_entry *kdbus_name_lock(struct kdbus_name_registry *reg,
					 const char *name)
{
	struct kdbus_name_entry *e = NULL;
	u32 hash = kdbus_str_hash(name);

	down_read(&reg->rwlock);
	e = kdbus_name_lookup(reg, hash, name);
	if (e)
		return e;
	up_read(&reg->rwlock);

	return NULL;
}

/**
 * kdbus_name_unlock() - unlock one name in a name registry
 * @reg:		The name registry
 * @entry:		The locked name entry or NULL
 *
 * This is the unlock-counterpart of kdbus_name_lock(). It unlocks a name that
 * was previously successfully locked. You can safely pass NULL as entry and
 * this will become a no-op. Therefore, it's safe to always call this on the
 * return-value of kdbus_name_lock().
 *
 * Return: This always returns NULL.
 */
struct kdbus_name_entry *kdbus_name_unlock(struct kdbus_name_registry *reg,
					   struct kdbus_name_entry *entry)
{
	if (entry) {
		BUG_ON(!rwsem_is_locked(&reg->rwlock));
		up_read(&reg->rwlock);
	}

	return NULL;
}

static int kdbus_name_queue_conn(struct kdbus_conn *conn, u64 flags,
				 struct kdbus_name_entry *e)
{
	struct kdbus_name_queue_item *q;

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	q->conn = conn;
	q->flags = flags;
	q->entry = e;

	list_add_tail(&q->entry_entry, &e->queue_list);
	list_add_tail(&q->conn_entry, &conn->names_queue_list);

	return 0;
}

/**
 * kdbus_name_is_valid() - check if a name is valid
 * @p:			The name to check
 * @allow_wildcard:	Whether or not to allow a wildcard name
 *
 * A name is valid if all of the following criterias are met:
 *
 *  - The name has two or more elements separated by a period ('.') character.
 *  - All elements must contain at least one character.
 *  - Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_-"
 *    and must not begin with a digit.
 *  - The name must not exceed KDBUS_NAME_MAX_LEN.
 *  - If @allow_wildcard is true, the name may end on '.*'
 */
bool kdbus_name_is_valid(const char *p, bool allow_wildcard)
{
	bool dot, found_dot = false;
	const char *q;

	for (dot = true, q = p; *q; q++) {
		if (*q == '.') {
			if (dot)
				return false;

			found_dot = true;
			dot = true;
		} else {
			bool good;

			good = isalpha(*q) || (!dot && isdigit(*q)) ||
				*q == '_' || *q == '-' ||
				(allow_wildcard && dot &&
					*q == '*' && *(q + 1) == '\0');

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

/**
 * kdbus_name_acquire() - acquire a name
 * @reg:		The name registry
 * @conn:		The connection to pin this entry to
 * @name:		The name to acquire
 * @flags:		Acquisition flags (KDBUS_NAME_*)
 * @entry:		Return pointer for the entry (may be NULL)
 *
 * Callers must ensure that @conn is either a privileged bus user or has
 * sufficient privileges in the policy-db to own the well-known name @name.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       const char *name, u64 *flags,
		       struct kdbus_name_entry **entry)
{
	struct kdbus_name_entry *e = NULL;
	u32 hash;
	int ret = 0;

	/* lock order: domain -> bus -> ep -> names -> conn */
	mutex_lock(&conn->bus->lock);
	down_write(&reg->rwlock);

	hash = kdbus_str_hash(name);
	e = kdbus_name_lookup(reg, hash, name);
	if (e) {
		/* connection already owns that name */
		if (e->conn == conn) {
			ret = -EALREADY;
			goto exit_unlock;
		}

		if (kdbus_conn_is_activator(conn)) {
			/* An activator can only own a single name */
			if (conn->activator_of) {
				if (conn->activator_of == e)
					ret = -EALREADY;
				else
					ret = -EINVAL;
			} else if (!e->activator && !conn->activator_of) {
				/*
				 * Activator registers for name that is
				 * already owned
				 */
				e->activator = kdbus_conn_ref(conn);
				conn->activator_of = e;
			}

			goto exit_unlock;
		}

		/* take over the name of an activator connection */
		if (e->flags & KDBUS_NAME_ACTIVATOR) {
			/*
			 * Take over the messages queued in the activator
			 * connection, the activator itself never reads them.
			 */
			ret = kdbus_conn_move_messages(conn, e->activator, 0);
			if (ret < 0)
				goto exit_unlock;

			ret = kdbus_name_replace_owner(e, conn, *flags);
			goto exit_unlock;
		}

		/* take over the name if both parties agree */
		if ((*flags & KDBUS_NAME_REPLACE_EXISTING) &&
		    (e->flags & KDBUS_NAME_ALLOW_REPLACEMENT)) {
			/*
			 * Move name back to the queue, in case we take it away
			 * from a connection which asked for queuing.
			 */
			if (e->flags & KDBUS_NAME_QUEUE) {
				ret = kdbus_name_queue_conn(e->conn,
							    e->flags, e);
				if (ret < 0)
					goto exit_unlock;
			}

			ret = kdbus_name_replace_owner(e, conn, *flags);
			goto exit_unlock;
		}

		/* add it to the queue waiting for the name */
		if (*flags & KDBUS_NAME_QUEUE) {
			ret = kdbus_name_queue_conn(conn, *flags, e);

			/* tell the caller that we queued it */
			*flags |= KDBUS_NAME_IN_QUEUE;

			goto exit_unlock;
		}

		/* the name is busy, return a failure */
		ret = -EEXIST;
		goto exit_unlock;
	} else {
		/* An activator can only own a single name */
		if (kdbus_conn_is_activator(conn) &&
		    conn->activator_of) {
			ret = -EINVAL;
			goto exit_unlock;
		}
	}

	/* new name entry */
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

	if (kdbus_conn_is_activator(conn)) {
		e->activator = kdbus_conn_ref(conn);
		conn->activator_of = e;
	}

	e->flags = *flags;
	INIT_LIST_HEAD(&e->queue_list);
	e->name_id = ++reg->name_seq_last;

	mutex_lock(&conn->lock);
	if (!kdbus_conn_active(conn)) {
		mutex_unlock(&conn->lock);
		kfree(e);
		ret = -ECONNRESET;
		goto exit_unlock;
	}
	hash_add(reg->entries_hash, &e->hentry, hash);
	kdbus_name_entry_set_owner(e, conn);
	mutex_unlock(&conn->lock);

	kdbus_notify_name_change(e->conn->bus, KDBUS_ITEM_NAME_ADD,
				 0, e->conn->id,
				 0, e->flags, e->name);

	if (entry)
		*entry = e;

exit_unlock:
	up_write(&reg->rwlock);
	mutex_unlock(&conn->bus->lock);
	kdbus_notify_flush(conn->bus);

	return ret;
}

static int kdbus_cmd_name_get_name(const struct kdbus_cmd_name *cmd,
				   const char **name)
{
	const struct kdbus_item *item;
	const char *n = NULL;
	int ret;

	KDBUS_ITEMS_FOREACH(item, cmd->items, KDBUS_ITEMS_SIZE(cmd, items)) {
		if (!KDBUS_ITEM_VALID(item, &cmd->items,
				      KDBUS_ITEMS_SIZE(cmd, items)))
			return -EINVAL;

		switch (item->type) {
		case KDBUS_ITEM_NAME:
			ret = kdbus_item_validate_name(item);
			if (ret < 0)
				return ret;

			if (!kdbus_name_is_valid(item->str, false))
				return -EINVAL;

			if (n)
				return -EINVAL;

			n = item->str;
			break;
		}
	}

	if (!KDBUS_ITEMS_END(item, cmd->items, KDBUS_ITEMS_SIZE(cmd, items)))
		return -EINVAL;

	if (!n)
		return -EINVAL;

	*name = n;
	return 0;
}

/**
 * kdbus_cmd_name_acquire() - acquire a name from a ioctl command buffer
 * @reg:		The name registry
 * @conn:		The connection to pin this entry to
 * @cmd:		The command as passed in by the ioctl
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_cmd_name_acquire(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   struct kdbus_cmd_name *cmd)
{
	struct kdbus_name_entry *e = NULL;
	const char *name;
	u64 allowed;
	int ret;

	if (conn->name_count > KDBUS_CONN_MAX_NAMES)
		return -E2BIG;

	/* refuse improper flags when requesting */
	allowed = KDBUS_NAME_REPLACE_EXISTING  |
		  KDBUS_NAME_ALLOW_REPLACEMENT |
		  KDBUS_NAME_QUEUE;
	if ((cmd->flags & ~allowed) != 0)
		return -EINVAL;

	ret = kdbus_cmd_name_get_name(cmd, &name);
	if (ret < 0)
		return -EINVAL;

	ret = kdbus_ep_policy_check_own_access(conn->ep, conn, name);
	if (ret < 0)
		goto exit;

	ret = kdbus_name_acquire(reg, conn, name, &cmd->flags, &e);

exit:
	kdbus_notify_flush(conn->bus);
	return ret;
}

/**
 * kdbus_cmd_name_release() - release a name entry from a ioctl command buffer
 * @reg:		The name registry
 * @conn:		The connection that holds the name
 * @cmd:		The command as passed in by the ioctl
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_cmd_name_release(struct kdbus_name_registry *reg,
			   struct kdbus_conn *conn,
			   const struct kdbus_cmd_name *cmd)
{
	int ret;
	const char *name;

	ret = kdbus_cmd_name_get_name(cmd, &name);
	if (ret < 0)
		return -EINVAL;

	ret = kdbus_name_release(reg, conn, name);

	kdbus_notify_flush(conn->bus);
	return ret;
}

static int kdbus_name_list_write(struct kdbus_conn *conn,
				 struct kdbus_conn *c,
				 struct kdbus_pool_slice *slice,
				 size_t *pos,
				 struct kdbus_name_entry *e,
				 bool write)
{
	const size_t len = sizeof(struct kdbus_cmd_name);
	size_t p = *pos;
	size_t nlen = 0;

	if (e) {
		nlen = strlen(e->name) + 1;

		if (kdbus_ep_policy_check_see_access_unlocked(conn->ep, conn,
							      e->name) < 0)
			return 0;
	}

	if (write) {
		int ret;
		struct kdbus_cmd_name n = {
			.size = len,
			.owner_id = c->id,
			.flags = e ? e->flags : 0,
			.conn_flags = c->flags,
		};

		if (nlen)
			n.size += KDBUS_ITEM_SIZE(nlen);

		/* write record */
		ret = kdbus_pool_slice_copy(slice, p, &n, len);
		if (ret < 0)
			return ret;
		p += len;

		/* append name */
		if (e) {
			struct kdbus_item_header {
				__u64 size;
				__u64 type;
			} h;

			h.size = KDBUS_ITEM_HEADER_SIZE + nlen;
			h.type = KDBUS_ITEM_NAME;

			ret = kdbus_pool_slice_copy(slice, p, &h, sizeof(h));
			if (ret < 0)
				return ret;

			p += sizeof(h);

			ret = kdbus_pool_slice_copy(slice, p, e->name, nlen);
			if (ret < 0)
				return ret;

			p += KDBUS_ALIGN8(nlen);
		}
	} else {
		p += len;
		if (nlen)
			p += KDBUS_ITEM_SIZE(nlen);
	}

	*pos = p;
	return 0;
}

static int kdbus_name_list_all(struct kdbus_conn *conn, u64 flags,
			       struct kdbus_pool_slice *slice,
			       size_t *pos, bool write)
{
	struct kdbus_conn *c;
	size_t p = *pos;
	int ret, i;

	hash_for_each(conn->bus->conn_hash, i, c, hentry) {
		bool added = false;

		/* skip activators */
		if (!(flags & KDBUS_NAME_LIST_ACTIVATORS) &&
		    kdbus_conn_is_activator(c))
			continue;

		/* all names the connection owns */
		if (flags & (KDBUS_NAME_LIST_NAMES |
			     KDBUS_NAME_LIST_ACTIVATORS)) {
			struct kdbus_name_entry *e;

			mutex_lock(&c->lock);
			list_for_each_entry(e, &c->names_list, conn_entry) {
				struct kdbus_conn *a = e->activator;

				if ((flags & KDBUS_NAME_LIST_ACTIVATORS) &&
				    a && a != c) {
					ret = kdbus_name_list_write(conn, a,
							slice, &p, e, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				}

				if (flags & KDBUS_NAME_LIST_NAMES ||
				    kdbus_conn_is_activator(c)) {
					ret = kdbus_name_list_write(conn, c,
							slice, &p, e, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				}
			}
			mutex_unlock(&c->lock);
		}

		/* queue of names the connection is currently waiting for */
		if (flags & KDBUS_NAME_LIST_QUEUED) {
			struct kdbus_name_queue_item *q;

			mutex_lock(&c->lock);
			list_for_each_entry(q, &c->names_queue_list,
					    conn_entry) {
				ret = kdbus_name_list_write(conn, c,
						slice, &p, q->entry, write);
				if (ret < 0) {
					mutex_unlock(&c->lock);
					return ret;
				}

				added = true;
			}
			mutex_unlock(&c->lock);
		}

		/* nothing added so far, just add the unique ID */
		if (!added && flags & KDBUS_NAME_LIST_UNIQUE) {
			ret = kdbus_name_list_write(conn, c,
					slice, &p, NULL, write);
			if (ret < 0)
				return ret;
		}
	}

	*pos = p;
	return 0;
}

/**
 * kdbus_cmd_name_list() - list names of a connection
 * @reg:		The name registry
 * @conn:		The connection holding the name entries
 * @cmd:		The command as passed in by the ioctl
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_cmd_name_list(struct kdbus_name_registry *reg,
			struct kdbus_conn *conn,
			struct kdbus_cmd_name_list *cmd)
{
	struct kdbus_policy_db *policy_db;
	struct kdbus_name_list list = {};
	struct kdbus_pool_slice *slice;
	size_t pos;
	int ret;

	policy_db = &conn->ep->policy_db;

	/* lock order: domain -> bus -> ep -> names -> conn */
	down_read(&conn->bus->conn_rwlock);
	down_read(&reg->rwlock);
	down_read(&policy_db->entries_rwlock);

	/* size of header + records */
	pos = sizeof(struct kdbus_name_list);
	ret = kdbus_name_list_all(conn, cmd->flags, NULL, &pos, false);
	if (ret < 0)
		goto exit_unlock;

	ret = kdbus_pool_slice_alloc(conn->pool, &slice, pos);
	if (ret < 0)
		goto exit_unlock;

	/* copy the header, specifying the overall size */
	list.size = pos;
	ret = kdbus_pool_slice_copy(slice, 0, &list, sizeof(list));
	if (ret < 0)
		goto exit_pool_free;

	/* copy the records */
	pos = sizeof(struct kdbus_name_list);
	ret = kdbus_name_list_all(conn, cmd->flags, slice, &pos, true);
	if (ret < 0)
		goto exit_pool_free;

	cmd->offset = kdbus_pool_slice_offset(slice);
	kdbus_pool_slice_flush(slice);
	kdbus_pool_slice_make_public(slice);

exit_pool_free:
	if (ret < 0)
		kdbus_pool_slice_free(slice);
exit_unlock:
	up_read(&policy_db->entries_rwlock);
	up_read(&reg->rwlock);
	up_read(&conn->bus->conn_rwlock);
	return ret;
}
