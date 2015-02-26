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

	list_del(&p->name_entry);
	list_del(&p->conn_entry);
	kfree(p);
}

static struct kdbus_name_entry *
kdbus_name_entry_new(struct kdbus_name_registry *r, u32 hash, const char *name)
{
	struct kdbus_name_entry *e;
	size_t namelen;

	namelen = strlen(name);

	e = kmalloc(sizeof(*e) + namelen + 1, GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);

	e->name_id = ++r->name_seq_last;
	e->flags = 0;
	e->conn = NULL;
	e->activator = NULL;
	INIT_LIST_HEAD(&e->queue);
	INIT_LIST_HEAD(&e->conn_entry);
	hash_add(r->entries_hash, &e->hentry, hash);
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
				       struct kdbus_conn *conn, u64 flags)
{
	WARN_ON(e->conn);

	e->conn = kdbus_conn_ref(conn);
	e->flags = flags;
	atomic_inc(&conn->name_count);
	list_add_tail(&e->conn_entry, &e->conn->names_list);
}

static void kdbus_name_entry_remove_owner(struct kdbus_name_entry *e)
{
	WARN_ON(!e->conn);

	list_del_init(&e->conn_entry);
	atomic_dec(&e->conn->name_count);
	e->flags = 0;
	e->conn = kdbus_conn_unref(e->conn);
}

static void kdbus_name_entry_replace_owner(struct kdbus_name_entry *e,
					   struct kdbus_conn *conn, u64 flags)
{
	if (WARN_ON(!e->conn) || WARN_ON(conn == e->conn))
		return;

	kdbus_notify_name_change(conn->ep->bus, KDBUS_ITEM_NAME_CHANGE,
				 e->conn->id, conn->id,
				 e->flags, flags, e->name);
	kdbus_name_entry_remove_owner(e);
	kdbus_name_entry_set_owner(e, conn, flags);
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

	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);

	hash_init(r->entries_hash);
	init_rwsem(&r->rwlock);
	r->name_seq_last = 0;

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
	if (!reg)
		return;

	WARN_ON(!hash_empty(reg->entries_hash));
	kfree(reg);
}

static struct kdbus_name_entry *
kdbus_name_find(struct kdbus_name_registry *reg, u32 hash, const char *name)
{
	struct kdbus_name_entry *e;

	lockdep_assert_held(&reg->rwlock);

	hash_for_each_possible(reg->entries_hash, e, hentry, hash)
		if (strcmp(e->name, name) == 0)
			return e;

	return NULL;
}

/**
 * kdbus_name_lookup_unlocked() - lookup name in registry
 * @reg:		name registry
 * @name:		name to lookup
 *
 * This looks up @name in the given name-registry and returns the
 * kdbus_name_entry object. The caller must hold the registry-lock and must not
 * access the returned object after releasing the lock.
 *
 * Return: Pointer to name-entry, or NULL if not found.
 */
struct kdbus_name_entry *
kdbus_name_lookup_unlocked(struct kdbus_name_registry *reg, const char *name)
{
	return kdbus_name_find(reg, kdbus_strhash(name), name);
}

/**
 * kdbus_name_acquire() - acquire a name
 * @reg:		The name registry
 * @conn:		The connection to pin this entry to
 * @name:		The name to acquire
 * @flags:		Acquisition flags (KDBUS_NAME_*)
 * @return_flags:	Pointer to return flags for the acquired name
 *			(KDBUS_NAME_*), may be %NULL
 *
 * Callers must ensure that @conn is either a privileged bus user or has
 * sufficient privileges in the policy-db to own the well-known name @name.
 *
 * Return: 0 success, negative error number on failure.
 */
int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn, const char *name,
		       u64 flags, u64 *return_flags)
{
	struct kdbus_name_entry *e;
	u64 rflags = 0;
	int ret = 0;
	u32 hash;

	kdbus_conn_assert_active(conn);

	down_write(&reg->rwlock);

	if (!kdbus_conn_policy_own_name(conn, current_cred(), name)) {
		ret = -EPERM;
		goto exit_unlock;
	}

	hash = kdbus_strhash(name);
	e = kdbus_name_find(reg, hash, name);
	if (!e) {
		/* claim new name */

		if (conn->activator_of) {
			ret = -EINVAL;
			goto exit_unlock;
		}

		e = kdbus_name_entry_new(reg, hash, name);
		if (IS_ERR(e)) {
			ret = PTR_ERR(e);
			goto exit_unlock;
		}

		if (kdbus_conn_is_activator(conn)) {
			e->activator = kdbus_conn_ref(conn);
			conn->activator_of = e;
		}

		kdbus_name_entry_set_owner(e, conn, flags);
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
		kdbus_name_entry_replace_owner(e, conn, flags);
	} else if ((flags & KDBUS_NAME_REPLACE_EXISTING) &&
		   (e->flags & KDBUS_NAME_ALLOW_REPLACEMENT)) {
		/* claim name of a previous owner */

		if (e->flags & KDBUS_NAME_QUEUE) {
			/* move owner back to queue if they asked for it */
			ret = kdbus_name_pending_new(e, e->conn, e->flags);
			if (ret < 0)
				goto exit_unlock;
		}

		kdbus_name_entry_replace_owner(e, conn, flags);
	} else if (flags & KDBUS_NAME_QUEUE) {
		/* add to waiting-queue of the name */

		ret = kdbus_name_pending_new(e, conn, flags);
		if (ret >= 0)
			/* tell the caller that we queued it */
			rflags |= KDBUS_NAME_IN_QUEUE;
	} else {
		/* the name is busy, return a failure */
		ret = -EEXIST;
	}

	if (ret == 0 && return_flags)
		*return_flags = rflags;

exit_unlock:
	up_write(&reg->rwlock);
	kdbus_notify_flush(conn->ep->bus);
	return ret;
}

static void kdbus_name_release_unlocked(struct kdbus_name_registry *reg,
					struct kdbus_name_entry *e)
{
	struct kdbus_name_pending *p;

	lockdep_assert_held(&reg->rwlock);

	p = list_first_entry_or_null(&e->queue, struct kdbus_name_pending,
				     name_entry);

	if (p) {
		/* give it to first active waiter in the queue */
		kdbus_name_entry_replace_owner(e, p->conn, p->flags);
		kdbus_name_pending_free(p);
	} else if (e->activator && e->activator != e->conn) {
		/* hand it back to an active activator connection */
		kdbus_conn_move_messages(e->activator, e->conn, e->name_id);
		kdbus_name_entry_replace_owner(e, e->activator,
					       KDBUS_NAME_ACTIVATOR);
	} else {
		/* release the name */
		kdbus_notify_name_change(e->conn->ep->bus,
					 KDBUS_ITEM_NAME_REMOVE,
					 e->conn->id, 0, e->flags, 0, e->name);
		kdbus_name_entry_remove_owner(e);
		kdbus_name_entry_free(e);
	}
}

static int kdbus_name_release(struct kdbus_name_registry *reg,
			      struct kdbus_conn *conn,
			      const char *name)
{
	struct kdbus_name_pending *p;
	struct kdbus_name_entry *e;
	int ret = 0;

	down_write(&reg->rwlock);
	e = kdbus_name_find(reg, kdbus_strhash(name), name);
	if (!e) {
		ret = -ESRCH;
	} else if (e->conn == conn) {
		kdbus_name_release_unlocked(reg, e);
	} else {
		ret = -EADDRINUSE;
		list_for_each_entry(p, &e->queue, name_entry) {
			if (p->conn == conn) {
				kdbus_name_pending_free(p);
				ret = 0;
				break;
			}
		}
	}
	up_write(&reg->rwlock);

	kdbus_notify_flush(conn->ep->bus);
	return ret;
}

/**
 * kdbus_name_release_all() - remove all name entries of a given connection
 * @reg:		name registry
 * @conn:		connection
 */
void kdbus_name_release_all(struct kdbus_name_registry *reg,
			    struct kdbus_conn *conn)
{
	struct kdbus_name_pending *p;
	struct kdbus_conn *activator = NULL;
	struct kdbus_name_entry *e;

	down_write(&reg->rwlock);

	if (kdbus_conn_is_activator(conn)) {
		activator = conn->activator_of->activator;
		conn->activator_of->activator = NULL;
	}

	while ((p = list_first_entry_or_null(&conn->names_queue_list,
					     struct kdbus_name_pending,
					     conn_entry)))
		kdbus_name_pending_free(p);
	while ((e = list_first_entry_or_null(&conn->names_list,
					     struct kdbus_name_entry,
					     conn_entry)))
		kdbus_name_release_unlocked(reg, e);

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

	ret = kdbus_name_acquire(conn->ep->bus->name_registry, conn, item_name,
				 cmd->flags, &cmd->return_flags);
	if (ret < 0)
		goto exit_dec;

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

			list_for_each_entry(e, &c->names_list, conn_entry) {
				struct kdbus_conn *a = e->activator;

				if ((flags & KDBUS_LIST_ACTIVATORS) &&
				    a && a != c) {
					ret = kdbus_list_write(conn, a, slice,
							       &p, e, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				}

				if (flags & KDBUS_LIST_NAMES ||
				    kdbus_conn_is_activator(c)) {
					ret = kdbus_list_write(conn, c, slice,
							       &p, e, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				}
			}
		}

		/* queue of names the connection is currently waiting for */
		if (flags & KDBUS_LIST_QUEUED) {
			struct kdbus_name_pending *q;

			list_for_each_entry(q, &c->names_queue_list,
					    conn_entry) {
				ret = kdbus_list_write(conn, c, slice, &p,
						       q->name, write);
				if (ret < 0) {
					mutex_unlock(&c->lock);
					return ret;
				}

				added = true;
			}
		}

		/* nothing added so far, just add the unique ID */
		if (!added && flags & KDBUS_LIST_UNIQUE) {
			ret = kdbus_list_write(conn, c, slice, &p, NULL, write);
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
		slice = kdbus_pool_slice_alloc(conn->pool, size, false);
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
