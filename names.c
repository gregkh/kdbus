/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/ctype.h>
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
#include <linux/uio.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "handle.h"
#include "item.h"
#include "names.h"
#include "notify.h"
#include "policy.h"

struct kdbus_name_pending {
	u64 flags;
	struct kdbus_conn *conn;
	struct kdbus_name_entry *name;
	struct list_head conn_entry;
	struct list_head name_entry;
};

static int kdbus_name_pending_new(struct kdbus_name_entry *e,
				  struct kdbus_conn *conn, u64 flags)
{
	struct kdbus_name_pending *p;

	kdbus_conn_assert_active(conn);
	lockdep_assert_held(&conn->lock);

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->flags = flags;
	p->conn = conn;
	p->name = e;
	list_add_tail(&p->conn_entry, &conn->names_queue_list);
	list_add_tail(&p->name_entry, &e->queue);

	return 0;
}

static void kdbus_name_pending_free(struct kdbus_name_pending *p)
{
	if (!p)
		return;

	lockdep_assert_held(&p->conn->lock);

	list_del(&p->name_entry);
	list_del(&p->conn_entry);
	kfree(p);
}

static struct kdbus_name_entry *
kdbus_name_entry_new(struct kdbus_name_registry *reg, const char *name,
		     u64 flags)
{
	struct kdbus_name_entry *e;
	size_t namelen;

	namelen = strlen(name);

	e = kmalloc(sizeof(*e) + namelen + 1, GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);

	e->name_id = ++reg->name_seq_last;
	e->flags = flags;
	e->conn = NULL;
	e->activator = NULL;
	INIT_LIST_HEAD(&e->queue);
	INIT_LIST_HEAD(&e->conn_entry);
	INIT_HLIST_NODE(&e->hentry);
	memcpy(e->name, name, namelen + 1);

	return e;
}

static void kdbus_name_entry_free(struct kdbus_name_entry *e)
{
	if (!e)
		return;

	WARN_ON(!list_empty(&e->conn_entry));
	WARN_ON(!list_empty(&e->queue));
	WARN_ON(e->activator);
	WARN_ON(e->conn);

	hash_del(&e->hentry);
	kfree(e);
}

static void kdbus_name_entry_set_owner(struct kdbus_name_entry *e,
				       struct kdbus_conn *conn)
{
	WARN_ON(e->conn);
	lockdep_assert_held(&conn->lock);

	e->conn = kdbus_conn_ref(conn);
	atomic_inc(&conn->name_count);
	list_add_tail(&e->conn_entry, &e->conn->names_list);
}

static void kdbus_name_entry_remove_owner(struct kdbus_name_entry *e)
{
	WARN_ON(!e->conn);
	lockdep_assert_held(&e->conn->lock);

	list_del_init(&e->conn_entry);
	atomic_dec(&e->conn->name_count);
	e->conn = kdbus_conn_unref(e->conn);
}

static void kdbus_name_entry_replace_owner(struct kdbus_name_entry *e,
					   struct kdbus_conn *conn, u64 flags)
{
	struct kdbus_conn *conn_old;

	if (WARN_ON(!e->conn) || WARN_ON(conn == e->conn))
		return;

	kdbus_conn_assert_active(conn);

	conn_old = kdbus_conn_ref(e->conn);
	kdbus_conn_lock2(conn, conn_old);

	kdbus_notify_name_change(conn->ep->bus, KDBUS_ITEM_NAME_CHANGE,
				 e->conn->id, conn->id,
				 e->flags, flags, e->name);
	kdbus_name_entry_remove_owner(e);
	kdbus_name_entry_set_owner(e, conn);
	e->flags = flags;

	kdbus_conn_unlock2(conn, conn_old);
	kdbus_conn_unref(conn_old);
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
 * kdbus_name_registry_new() - create a new name registry
 *
 * Return: a new kdbus_name_registry on success, ERR_PTR on failure.
 */
struct kdbus_name_registry *kdbus_name_registry_new(void)
{
	struct kdbus_name_registry *r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);

	hash_init(r->entries_hash);
	init_rwsem(&r->rwlock);

	return r;
}

/**
 * kdbus_name_registry_free() - drop a name reg's reference
 * @reg:		The name registry, may be %NULL
 *
 * Cleanup the name registry's internal structures.
 */
void kdbus_name_registry_free(struct kdbus_name_registry *reg)
{
	struct kdbus_name_entry *e;
	struct hlist_node *tmp;
	unsigned int i;

	if (!reg)
		return;

	hash_for_each_safe(reg->entries_hash, i, tmp, e, hentry)
		kdbus_name_entry_free(e);

	kfree(reg);
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
 * protect their code against concurrent activator/implementer name changes.
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
	u32 hash = kdbus_strhash(name);

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

/**
 * kdbus_name_acquire() - acquire a name
 * @reg:		The name registry
 * @conn:		The connection to pin this entry to
 * @name:		The name to acquire
 * @flags:		Acquisition flags (KDBUS_NAME_*)
 *
 * Callers must ensure that @conn is either a privileged bus user or has
 * sufficient privileges in the policy-db to own the well-known name @name.
 *
 * Return: 0 success, negative error number on failure.
 */
int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       const char *name, u64 *flags)
{
	struct kdbus_name_entry *e;
	int ret = 0;
	u32 hash;

	kdbus_conn_assert_active(conn);

	down_write(&reg->rwlock);

	hash = kdbus_strhash(name);
	e = kdbus_name_lookup(reg, hash, name);
	if (!e) {
		/* claim new name */

		if (conn->activator_of) {
			ret = -EINVAL;
			goto exit_unlock;
		}

		e = kdbus_name_entry_new(reg, name, *flags);
		if (IS_ERR(e)) {
			ret = PTR_ERR(e);
			goto exit_unlock;
		}

		if (kdbus_conn_is_activator(conn)) {
			e->activator = kdbus_conn_ref(conn);
			conn->activator_of = e;
		}

		mutex_lock(&conn->lock);
		hash_add(reg->entries_hash, &e->hentry, hash);
		kdbus_name_entry_set_owner(e, conn);
		mutex_unlock(&conn->lock);

		kdbus_notify_name_change(e->conn->ep->bus, KDBUS_ITEM_NAME_ADD,
					 0, e->conn->id, 0, e->flags, e->name);
	} else if (e->conn == conn || e == conn->activator_of) {
		/* connection already owns that name */
		ret = -EALREADY;
	} else if (kdbus_conn_is_activator(conn)) {
		/* activator claims existing name */

		if (conn->activator_of) {
			ret = -EINVAL; /* multiple names not allowed */
		} else if (e->activator) {
			ret = -EEXIST; /* only one activator per name */
		} else {
			e->activator = kdbus_conn_ref(conn);
			conn->activator_of = e;
		}
	} else if (e->flags & KDBUS_NAME_ACTIVATOR) {
		/* claim name of an activator */

		kdbus_conn_move_messages(conn, e->activator, 0);
		kdbus_name_entry_replace_owner(e, conn, *flags);
	} else if ((*flags & KDBUS_NAME_REPLACE_EXISTING) &&
		   (e->flags & KDBUS_NAME_ALLOW_REPLACEMENT)) {
		/* claim name of a previous owner */

		if (e->flags & KDBUS_NAME_QUEUE) {
			/* move owner back to queue if they asked for it */
			ret = kdbus_name_pending_new(e, e->conn, e->flags);
			if (ret < 0)
				goto exit_unlock;
		}

		kdbus_name_entry_replace_owner(e, conn, *flags);
	} else if (*flags & KDBUS_NAME_QUEUE) {
		/* add to waiting-queue of the name */

		ret = kdbus_name_pending_new(e, conn, *flags);
		if (ret >= 0)
			/* tell the caller that we queued it */
			*flags |= KDBUS_NAME_IN_QUEUE;
	} else {
		/* the name is busy, return a failure */
		ret = -EEXIST;
	}

exit_unlock:
	up_write(&reg->rwlock);
	kdbus_notify_flush(conn->ep->bus);
	return ret;
}

static int kdbus_name_entry_release(struct kdbus_name_entry *e)
{
	struct kdbus_name_pending *p;
	struct kdbus_conn *conn;
	int ret;

	/* give it to first active waiter in the queue */
	if ((p = list_first_entry_or_null(&e->queue, struct kdbus_name_pending,
					  name_entry))) {
		kdbus_name_entry_replace_owner(e, p->conn, p->flags);
		kdbus_name_pending_free(p);
		return 0;
	}

	/* hand it back to an active activator connection */
	if (e->activator && e->activator != e->conn) {
		/* move pending messages of that name back to the activator */
		kdbus_conn_move_messages(e->activator, e->conn, e->name_id);
		kdbus_name_entry_replace_owner(e, e->activator,
					       KDBUS_NAME_ACTIVATOR);
		return 0;
	}

	/* release the name */
	kdbus_notify_name_change(e->conn->ep->bus, KDBUS_ITEM_NAME_REMOVE,
				 e->conn->id, 0, e->flags, 0, e->name);

	conn = kdbus_conn_ref(e->conn);
	mutex_lock(&conn->lock);
	kdbus_name_entry_remove_owner(e);
	mutex_unlock(&conn->lock);
	kdbus_conn_unref(conn);

	kdbus_name_entry_free(e);

	return 0;
}

static int kdbus_name_release(struct kdbus_name_registry *reg,
			      struct kdbus_conn *conn,
			      const char *name)
{
	struct kdbus_name_pending *p;
	struct kdbus_name_entry *e = NULL;
	int ret = -ESRCH;
	u32 hash;

	hash = kdbus_strhash(name);

	/* lock order: domain -> bus -> ep -> names -> connection */
	down_write(&reg->rwlock);

	e = kdbus_name_lookup(reg, hash, name);
	if (!e)
		goto exit_unlock;

	/* Is the connection already the real owner of the name? */
	if (e->conn == conn) {
		ret = kdbus_name_entry_release(e);
	} else {
		/* Otherwise, see if the connection is waiting in the queue */
		ret = -EADDRINUSE;
		list_for_each_entry(p, &e->queue, name_entry) {
			if (p->conn == conn) {
				kdbus_name_pending_free(p);
				ret = 0;
				break;
			}
		}
	}

exit_unlock:
	up_write(&reg->rwlock);

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
	struct kdbus_name_pending *p;
	struct kdbus_conn *activator = NULL;
	struct kdbus_name_entry *e_tmp, *e;
	LIST_HEAD(names_list);
	LIST_HEAD(queue);

	/* lock order: domain -> bus -> ep -> names -> conn */
	down_write(&reg->rwlock);

	mutex_lock(&conn->lock);
	list_splice_init(&conn->names_list, &names_list);
	list_splice_init(&conn->names_queue_list, &queue);
	mutex_unlock(&conn->lock);

	if (kdbus_conn_is_activator(conn)) {
		activator = conn->activator_of->activator;
		conn->activator_of->activator = NULL;
	}

	while ((p = list_first_entry_or_null(&queue, struct kdbus_name_pending,
					     conn_entry)))
		kdbus_name_pending_free(p);

	list_for_each_entry_safe(e, e_tmp, &names_list, conn_entry)
		kdbus_name_entry_release(e);

	up_write(&reg->rwlock);

	kdbus_conn_unref(activator);
	kdbus_notify_flush(conn->ep->bus);
}

/**
 * kdbus_cmd_name_acquire() - handle KDBUS_CMD_NAME_ACQUIRE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_name_acquire(struct kdbus_conn *conn, void __user *argp)
{
	const char *item_name;
	struct kdbus_cmd *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_NAME, .mandatory = true },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_NAME_REPLACE_EXISTING |
				 KDBUS_NAME_ALLOW_REPLACEMENT |
				 KDBUS_NAME_QUEUE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	item_name = argv[1].item->str;
	if (!kdbus_name_is_valid(item_name, false)) {
		ret = -EINVAL;
		goto exit;
	}

	/*
	 * Do atomic_inc_return here to reserve our slot, then decrement
	 * it before returning.
	 */
	if (atomic_inc_return(&conn->name_count) > KDBUS_CONN_MAX_NAMES) {
		ret = -E2BIG;
		goto exit_dec;
	}

	if (!kdbus_conn_policy_own_name(conn, current_cred(), item_name)) {
		ret = -EPERM;
		goto exit_dec;
	}

	ret = kdbus_name_acquire(conn->ep->bus->name_registry, conn, item_name,
				 &cmd->flags);
	if (ret < 0)
		goto exit_dec;

	/* TODO: we should not return data in cmd->flags! */
	if (copy_to_user(argp, cmd, cmd->size))
		ret = -EFAULT;

exit_dec:
	atomic_dec(&conn->name_count);
exit:
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_name_release() - handle KDBUS_CMD_NAME_RELEASE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_name_release(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_cmd *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_NAME, .mandatory = true },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	ret = kdbus_name_release(conn->ep->bus->name_registry, conn,
				 argv[1].item->str);
	kdbus_notify_flush(conn->ep->bus);
	return kdbus_args_clear(&args, ret);
}

static int kdbus_list_write(struct kdbus_conn *conn,
			    struct kdbus_conn *c,
			    struct kdbus_pool_slice *slice,
			    size_t *pos,
			    struct kdbus_name_entry *e,
			    bool write)
{
	struct kvec kvec[4];
	size_t cnt = 0;
	int ret;

	/* info header */
	struct kdbus_info info = {
		.size = 0,
		.id = c->id,
		.flags = c->flags,
	};

	/* fake the header of a kdbus_name item */
	struct {
		u64 size;
		u64 type;
		u64 flags;
	} h = {};

	if (e && !kdbus_conn_policy_see_name_unlocked(conn, current_cred(),
						      e->name))
		return 0;

	kdbus_kvec_set(&kvec[cnt++], &info, sizeof(info), &info.size);

	/* append name */
	if (e) {
		size_t slen = strlen(e->name) + 1;

		h.size = offsetof(struct kdbus_item, name.name) + slen;
		h.type = KDBUS_ITEM_OWNED_NAME;
		h.flags = e->flags;

		kdbus_kvec_set(&kvec[cnt++], &h, sizeof(h), &info.size);
		kdbus_kvec_set(&kvec[cnt++], e->name, slen, &info.size);
		cnt += !!kdbus_kvec_pad(&kvec[cnt], &info.size);
	}

	if (write) {
		ret = kdbus_pool_slice_copy_kvec(slice, *pos, kvec,
						 cnt, info.size);
		if (ret < 0)
			return ret;
	}

	*pos += info.size;
	return 0;
}

static int kdbus_list_all(struct kdbus_conn *conn, u64 flags,
			  struct kdbus_pool_slice *slice,
			  size_t *pos, bool write)
{
	struct kdbus_conn *c;
	size_t p = *pos;
	int ret, i;

	hash_for_each(conn->ep->bus->conn_hash, i, c, hentry) {
		bool added = false;

		/* skip monitors */
		if (kdbus_conn_is_monitor(c))
			continue;

		/* skip activators */
		if (!(flags & KDBUS_LIST_ACTIVATORS) &&
		    kdbus_conn_is_activator(c))
			continue;

		/* all names the connection owns */
		if (flags & (KDBUS_LIST_NAMES | KDBUS_LIST_ACTIVATORS)) {
			struct kdbus_name_entry *e;

			mutex_lock(&c->lock);
			list_for_each_entry(e, &c->names_list, conn_entry) {
				struct kdbus_conn *a = e->activator;

				if ((flags & KDBUS_LIST_ACTIVATORS) &&
				    a && a != c) {
					ret = kdbus_list_write(conn, a,
							slice, &p, e, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				}

				if (flags & KDBUS_LIST_NAMES ||
				    kdbus_conn_is_activator(c)) {
					ret = kdbus_list_write(conn, c,
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
		if (flags & KDBUS_LIST_QUEUED) {
			struct kdbus_name_pending *q;

			mutex_lock(&c->lock);
			list_for_each_entry(q, &c->names_queue_list,
					    conn_entry) {
				ret = kdbus_list_write(conn, c,
						slice, &p, q->name, write);
				if (ret < 0) {
					mutex_unlock(&c->lock);
					return ret;
				}

				added = true;
			}
			mutex_unlock(&c->lock);
		}

		/* nothing added so far, just add the unique ID */
		if (!added && flags & KDBUS_LIST_UNIQUE) {
			ret = kdbus_list_write(conn, c,
					slice, &p, NULL, write);
			if (ret < 0)
				return ret;
		}
	}

	*pos = p;
	return 0;
}

/**
 * kdbus_cmd_list() - handle KDBUS_CMD_LIST
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_list(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_name_registry *reg = conn->ep->bus->name_registry;
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_cmd_list *cmd;
	size_t pos, size;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_LIST_UNIQUE |
				 KDBUS_LIST_NAMES |
				 KDBUS_LIST_ACTIVATORS |
				 KDBUS_LIST_QUEUED,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	/* lock order: domain -> bus -> ep -> names -> conn */
	down_read(&reg->rwlock);
	down_read(&conn->ep->bus->conn_rwlock);
	down_read(&conn->ep->policy_db.entries_rwlock);

	/* size of records */
	size = 0;
	ret = kdbus_list_all(conn, cmd->flags, NULL, &size, false);
	if (ret < 0)
		goto exit_unlock;

	if (size == 0) {
		kdbus_pool_publish_empty(conn->pool, &cmd->offset,
					 &cmd->list_size);
	} else {
		slice = kdbus_pool_slice_alloc(conn->pool, size);
		if (IS_ERR(slice)) {
			ret = PTR_ERR(slice);
			slice = NULL;
			goto exit_unlock;
		}

		/* copy the records */
		pos = 0;
		ret = kdbus_list_all(conn, cmd->flags, slice, &pos, true);
		if (ret < 0)
			goto exit_unlock;

		WARN_ON(pos != size);
		kdbus_pool_slice_publish(slice, &cmd->offset, &cmd->list_size);
	}

	if (kdbus_member_set_user(&cmd->offset, argp, typeof(*cmd), offset) ||
	    kdbus_member_set_user(&cmd->list_size, argp,
				  typeof(*cmd), list_size))
		ret = -EFAULT;

exit_unlock:
	up_read(&conn->ep->policy_db.entries_rwlock);
	up_read(&conn->ep->bus->conn_rwlock);
	up_read(&reg->rwlock);
	kdbus_pool_slice_release(slice);
	return kdbus_args_clear(&args, ret);
}
