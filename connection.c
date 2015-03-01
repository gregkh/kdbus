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

#include <linux/audit.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "handle.h"
#include "match.h"
#include "message.h"
#include "metadata.h"
#include "names.h"
#include "domain.h"
#include "item.h"
#include "notify.h"
#include "policy.h"
#include "pool.h"
#include "reply.h"
#include "util.h"
#include "queue.h"

#define KDBUS_CONN_ACTIVE_BIAS	(INT_MIN + 2)
#define KDBUS_CONN_ACTIVE_NEW	(INT_MIN + 1)

static struct kdbus_conn *kdbus_conn_new(struct kdbus_ep *ep, bool privileged,
					 struct kdbus_cmd_hello *hello,
					 const char *name,
					 const struct kdbus_creds *creds,
					 const struct kdbus_pids *pids,
					 const char *seclabel,
					 const char *conn_description)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	static struct lock_class_key __key;
#endif
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_bus *bus = ep->bus;
	struct kdbus_conn *conn;
	u64 attach_flags_send;
	u64 attach_flags_recv;
	u64 items_size = 0;
	bool is_policy_holder;
	bool is_activator;
	bool is_monitor;
	struct kvec kvec;
	int ret;

	struct {
		u64 size;
		u64 type;
		struct kdbus_bloom_parameter bloom;
	} bloom_item;

	is_monitor = hello->flags & KDBUS_HELLO_MONITOR;
	is_activator = hello->flags & KDBUS_HELLO_ACTIVATOR;
	is_policy_holder = hello->flags & KDBUS_HELLO_POLICY_HOLDER;

	if (!hello->pool_size || !IS_ALIGNED(hello->pool_size, PAGE_SIZE))
		return ERR_PTR(-EINVAL);
	if (is_monitor + is_activator + is_policy_holder > 1)
		return ERR_PTR(-EINVAL);
	if (name && !is_activator && !is_policy_holder)
		return ERR_PTR(-EINVAL);
	if (!name && (is_activator || is_policy_holder))
		return ERR_PTR(-EINVAL);
	if (name && !kdbus_name_is_valid(name, true))
		return ERR_PTR(-EINVAL);
	if (is_monitor && ep->user)
		return ERR_PTR(-EOPNOTSUPP);
	if (!privileged && (is_activator || is_policy_holder || is_monitor))
		return ERR_PTR(-EPERM);
	if ((creds || pids || seclabel) && !privileged)
		return ERR_PTR(-EPERM);

	ret = kdbus_sanitize_attach_flags(hello->attach_flags_send,
					  &attach_flags_send);
	if (ret < 0)
		return ERR_PTR(ret);

	ret = kdbus_sanitize_attach_flags(hello->attach_flags_recv,
					  &attach_flags_recv);
	if (ret < 0)
		return ERR_PTR(ret);

	/* The attach flags must always satisfy the bus requirements. */
	if (bus->attach_flags_req & ~attach_flags_send)
		return ERR_PTR(-ECONNREFUSED);

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return ERR_PTR(-ENOMEM);

	kref_init(&conn->kref);
	atomic_set(&conn->active, KDBUS_CONN_ACTIVE_NEW);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	lockdep_init_map(&conn->dep_map, "s_active", &__key, 0);
#endif
	mutex_init(&conn->lock);
	INIT_LIST_HEAD(&conn->names_list);
	INIT_LIST_HEAD(&conn->names_queue_list);
	INIT_LIST_HEAD(&conn->reply_list);
	atomic_set(&conn->name_count, 0);
	atomic_set(&conn->request_count, 0);
	atomic_set(&conn->lost_count, 0);
	INIT_DELAYED_WORK(&conn->work, kdbus_reply_list_scan_work);
	conn->cred = get_current_cred();
	init_waitqueue_head(&conn->wait);
	kdbus_queue_init(&conn->queue);
	conn->privileged = privileged;
	conn->ep = kdbus_ep_ref(ep);
	conn->id = atomic64_inc_return(&bus->domain->last_id);
	conn->flags = hello->flags;
	atomic64_set(&conn->attach_flags_send, attach_flags_send);
	atomic64_set(&conn->attach_flags_recv, attach_flags_recv);
	INIT_LIST_HEAD(&conn->monitor_entry);

	if (conn_description) {
		conn->description = kstrdup(conn_description, GFP_KERNEL);
		if (!conn->description) {
			ret = -ENOMEM;
			goto exit_unref;
		}
	}

	conn->pool = kdbus_pool_new(conn->description, hello->pool_size);
	if (IS_ERR(conn->pool)) {
		ret = PTR_ERR(conn->pool);
		conn->pool = NULL;
		goto exit_unref;
	}

	conn->match_db = kdbus_match_db_new();
	if (IS_ERR(conn->match_db)) {
		ret = PTR_ERR(conn->match_db);
		conn->match_db = NULL;
		goto exit_unref;
	}

	/* return properties of this connection to the caller */
	hello->bus_flags = bus->bus_flags;
	hello->id = conn->id;

	BUILD_BUG_ON(sizeof(bus->id128) != sizeof(hello->id128));
	memcpy(hello->id128, bus->id128, sizeof(hello->id128));

	conn->meta = kdbus_meta_proc_new();
	if (IS_ERR(conn->meta)) {
		ret = PTR_ERR(conn->meta);
		conn->meta = NULL;
		goto exit_unref;
	}

	/* privileged processes can impersonate somebody else */
	if (creds || pids || seclabel) {
		ret = kdbus_meta_proc_fake(conn->meta, creds, pids, seclabel);
		if (ret < 0)
			goto exit_unref;

		conn->faked_meta = true;
	} else {
		ret = kdbus_meta_proc_collect(conn->meta,
					      KDBUS_ATTACH_CREDS |
					      KDBUS_ATTACH_PIDS |
					      KDBUS_ATTACH_AUXGROUPS |
					      KDBUS_ATTACH_TID_COMM |
					      KDBUS_ATTACH_PID_COMM |
					      KDBUS_ATTACH_EXE |
					      KDBUS_ATTACH_CMDLINE |
					      KDBUS_ATTACH_CGROUP |
					      KDBUS_ATTACH_CAPS |
					      KDBUS_ATTACH_SECLABEL |
					      KDBUS_ATTACH_AUDIT);
		if (ret < 0)
			goto exit_unref;
	}

	/*
	 * Account the connection against the current user (UID), or for
	 * custom endpoints use the anonymous user assigned to the endpoint.
	 * Note that limits are always accounted against the real UID, not
	 * the effective UID (cred->user always points to the accounting of
	 * cred->uid, not cred->euid).
	 */
	if (ep->user) {
		conn->user = kdbus_user_ref(ep->user);
	} else {
		conn->user = kdbus_user_lookup(ep->bus->domain, current_uid());
		if (IS_ERR(conn->user)) {
			ret = PTR_ERR(conn->user);
			conn->user = NULL;
			goto exit_unref;
		}
	}

	if (atomic_inc_return(&conn->user->connections) > KDBUS_USER_MAX_CONN) {
		/* decremented by destructor as conn->user is valid */
		ret = -EMFILE;
		goto exit_unref;
	}

	bloom_item.size = sizeof(bloom_item);
	bloom_item.type = KDBUS_ITEM_BLOOM_PARAMETER;
	bloom_item.bloom = bus->bloom;
	kdbus_kvec_set(&kvec, &bloom_item, bloom_item.size, &items_size);

	slice = kdbus_pool_slice_alloc(conn->pool, items_size, false);
	if (IS_ERR(slice)) {
		ret = PTR_ERR(slice);
		slice = NULL;
		goto exit_unref;
	}

	ret = kdbus_pool_slice_copy_kvec(slice, 0, &kvec, 1, items_size);
	if (ret < 0)
		goto exit_unref;

	kdbus_pool_slice_publish(slice, &hello->offset, &hello->items_size);
	kdbus_pool_slice_release(slice);

	return conn;

exit_unref:
	kdbus_pool_slice_release(slice);
	kdbus_conn_unref(conn);
	return ERR_PTR(ret);
}

static void __kdbus_conn_free(struct kref *kref)
{
	struct kdbus_conn *conn = container_of(kref, struct kdbus_conn, kref);

	WARN_ON(kdbus_conn_active(conn));
	WARN_ON(delayed_work_pending(&conn->work));
	WARN_ON(!list_empty(&conn->queue.msg_list));
	WARN_ON(!list_empty(&conn->names_list));
	WARN_ON(!list_empty(&conn->names_queue_list));
	WARN_ON(!list_empty(&conn->reply_list));

	if (conn->user) {
		atomic_dec(&conn->user->connections);
		kdbus_user_unref(conn->user);
	}

	kdbus_meta_proc_unref(conn->meta);
	kdbus_match_db_free(conn->match_db);
	kdbus_pool_free(conn->pool);
	kdbus_ep_unref(conn->ep);
	put_cred(conn->cred);
	kfree(conn->description);
	kfree(conn->quota);
	kfree(conn);
}

/**
 * kdbus_conn_ref() - take a connection reference
 * @conn:		Connection, may be %NULL
 *
 * Return: the connection itself
 */
struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn)
{
	if (conn)
		kref_get(&conn->kref);
	return conn;
}

/**
 * kdbus_conn_unref() - drop a connection reference
 * @conn:		Connection (may be NULL)
 *
 * When the last reference is dropped, the connection's internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_conn *kdbus_conn_unref(struct kdbus_conn *conn)
{
	if (conn)
		kref_put(&conn->kref, __kdbus_conn_free);
	return NULL;
}

/**
 * kdbus_conn_active() - connection is not disconnected
 * @conn:		Connection to check
 *
 * Return true if the connection was not disconnected, yet. Note that a
 * connection might be disconnected asynchronously, unless you hold the
 * connection lock. If that's not suitable for you, see kdbus_conn_acquire() to
 * suppress connection shutdown for a short period.
 *
 * Return: true if the connection is still active
 */
bool kdbus_conn_active(const struct kdbus_conn *conn)
{
	return atomic_read(&conn->active) >= 0;
}

/**
 * kdbus_conn_acquire() - acquire an active connection reference
 * @conn:		Connection
 *
 * Users can close a connection via KDBUS_BYEBYE (or by destroying the
 * endpoint/bus/...) at any time. Whenever this happens, we should deny any
 * user-visible action on this connection and signal ECONNRESET instead.
 * To avoid testing for connection availability everytime you take the
 * connection-lock, you can acquire a connection for short periods.
 *
 * By calling kdbus_conn_acquire(), you gain an "active reference" to the
 * connection. You must also hold a regular reference at any time! As long as
 * you hold the active-ref, the connection will not be shut down. However, if
 * the connection was shut down, you can never acquire an active-ref again.
 *
 * kdbus_conn_disconnect() disables the connection and then waits for all active
 * references to be dropped. It will also wake up any pending operation.
 * However, you must not sleep for an indefinite period while holding an
 * active-reference. Otherwise, kdbus_conn_disconnect() might stall. If you need
 * to sleep for an indefinite period, either release the reference and try to
 * acquire it again after waking up, or make kdbus_conn_disconnect() wake up
 * your wait-queue.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_conn_acquire(struct kdbus_conn *conn)
{
	if (!atomic_inc_unless_negative(&conn->active))
		return -ECONNRESET;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire_read(&conn->dep_map, 0, 1, _RET_IP_);
#endif

	return 0;
}

/**
 * kdbus_conn_release() - release an active connection reference
 * @conn:		Connection
 *
 * This releases an active reference that has been acquired via
 * kdbus_conn_acquire(). If the connection was already disabled and this is the
 * last active-ref that is dropped, the disconnect-waiter will be woken up and
 * properly close the connection.
 */
void kdbus_conn_release(struct kdbus_conn *conn)
{
	int v;

	if (!conn)
		return;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_release(&conn->dep_map, 1, _RET_IP_);
#endif

	v = atomic_dec_return(&conn->active);
	if (v != KDBUS_CONN_ACTIVE_BIAS)
		return;

	wake_up_all(&conn->wait);
}

static int kdbus_conn_connect(struct kdbus_conn *conn, const char *name)
{
	struct kdbus_ep *ep = conn->ep;
	struct kdbus_bus *bus = ep->bus;
	int ret;

	if (WARN_ON(atomic_read(&conn->active) != KDBUS_CONN_ACTIVE_NEW))
		return -EALREADY;

	/* make sure the ep-node is active while we add our connection */
	if (!kdbus_node_acquire(&ep->node))
		return -ESHUTDOWN;

	/* lock order: domain -> bus -> ep -> names -> conn */
	mutex_lock(&ep->lock);
	down_write(&bus->conn_rwlock);

	/* link into monitor list */
	if (kdbus_conn_is_monitor(conn))
		list_add_tail(&conn->monitor_entry, &bus->monitors_list);

	/* link into bus and endpoint */
	list_add_tail(&conn->ep_entry, &ep->conn_list);
	hash_add(bus->conn_hash, &conn->hentry, conn->id);

	/* enable lookups and acquire active ref */
	atomic_set(&conn->active, 1);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire_read(&conn->dep_map, 0, 1, _RET_IP_);
#endif

	up_write(&bus->conn_rwlock);
	mutex_unlock(&ep->lock);

	kdbus_node_release(&ep->node);

	/*
	 * Notify subscribers about the new active connection, unless it is
	 * a monitor. Monitors are invisible on the bus, can't be addressed
	 * directly, and won't cause any notifications.
	 */
	if (!kdbus_conn_is_monitor(conn)) {
		ret = kdbus_notify_id_change(conn->ep->bus, KDBUS_ITEM_ID_ADD,
					     conn->id, conn->flags);
		if (ret < 0)
			goto exit_disconnect;
	}

	if (kdbus_conn_is_activator(conn)) {
		u64 flags = KDBUS_NAME_ACTIVATOR;

		if (WARN_ON(!name)) {
			ret = -EINVAL;
			goto exit_disconnect;
		}

		ret = kdbus_name_acquire(bus->name_registry, conn, name,
					 flags, NULL);
		if (ret < 0)
			goto exit_disconnect;
	}

	kdbus_conn_release(conn);
	kdbus_notify_flush(bus);
	return 0;

exit_disconnect:
	kdbus_conn_release(conn);
	kdbus_conn_disconnect(conn, false);
	return ret;
}

/**
 * kdbus_conn_disconnect() - disconnect a connection
 * @conn:		The connection to disconnect
 * @ensure_queue_empty:	Flag to indicate if the call should fail in
 *			case the connection's message list is not
 *			empty
 *
 * If @ensure_msg_list_empty is true, and the connection has pending messages,
 * -EBUSY is returned.
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_conn_disconnect(struct kdbus_conn *conn, bool ensure_queue_empty)
{
	struct kdbus_queue_entry *entry, *tmp;
	struct kdbus_bus *bus = conn->ep->bus;
	struct kdbus_reply *r, *r_tmp;
	struct kdbus_conn *c;
	int i, v;

	mutex_lock(&conn->lock);
	v = atomic_read(&conn->active);
	if (v == KDBUS_CONN_ACTIVE_NEW) {
		/* was never connected */
		mutex_unlock(&conn->lock);
		return 0;
	}
	if (v < 0) {
		/* already dead */
		mutex_unlock(&conn->lock);
		return -ECONNRESET;
	}
	if (ensure_queue_empty && !list_empty(&conn->queue.msg_list)) {
		/* still busy */
		mutex_unlock(&conn->lock);
		return -EBUSY;
	}

	atomic_add(KDBUS_CONN_ACTIVE_BIAS, &conn->active);
	mutex_unlock(&conn->lock);

	wake_up_interruptible(&conn->wait);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire(&conn->dep_map, 0, 0, _RET_IP_);
	if (atomic_read(&conn->active) != KDBUS_CONN_ACTIVE_BIAS)
		lock_contended(&conn->dep_map, _RET_IP_);
#endif

	wait_event(conn->wait,
		   atomic_read(&conn->active) == KDBUS_CONN_ACTIVE_BIAS);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	lock_acquired(&conn->dep_map, _RET_IP_);
	rwsem_release(&conn->dep_map, 1, _RET_IP_);
#endif

	cancel_delayed_work_sync(&conn->work);
	kdbus_policy_remove_owner(&conn->ep->bus->policy_db, conn);

	/* lock order: domain -> bus -> ep -> names -> conn */
	mutex_lock(&conn->ep->lock);
	down_write(&bus->conn_rwlock);

	/* remove from bus and endpoint */
	hash_del(&conn->hentry);
	list_del(&conn->monitor_entry);
	list_del(&conn->ep_entry);

	up_write(&bus->conn_rwlock);
	mutex_unlock(&conn->ep->lock);

	/*
	 * Remove all names associated with this connection; this possibly
	 * moves queued messages back to the activator connection.
	 */
	kdbus_name_release_all(bus->name_registry, conn);

	/* if we die while other connections wait for our reply, notify them */
	mutex_lock(&conn->lock);
	list_for_each_entry_safe(entry, tmp, &conn->queue.msg_list, entry) {
		if (entry->reply)
			kdbus_notify_reply_dead(bus,
						entry->reply->reply_dst->id,
						entry->reply->cookie);
		kdbus_queue_entry_free(entry);
	}

	list_for_each_entry_safe(r, r_tmp, &conn->reply_list, entry)
		kdbus_reply_unlink(r);
	mutex_unlock(&conn->lock);

	/* lock order: domain -> bus -> ep -> names -> conn */
	down_read(&bus->conn_rwlock);
	hash_for_each(bus->conn_hash, i, c, hentry) {
		mutex_lock(&c->lock);
		list_for_each_entry_safe(r, r_tmp, &c->reply_list, entry) {
			if (r->reply_src == conn) {
				if (r->sync) {
					kdbus_sync_reply_wakeup(r, -EPIPE);
					kdbus_reply_unlink(r);
					continue;
				}

				/* send a 'connection dead' notification */
				kdbus_notify_reply_dead(bus, c->id, r->cookie);
				kdbus_reply_unlink(r);
			}
		}
		mutex_unlock(&c->lock);
	}
	up_read(&bus->conn_rwlock);

	if (!kdbus_conn_is_monitor(conn))
		kdbus_notify_id_change(bus, KDBUS_ITEM_ID_REMOVE,
				       conn->id, conn->flags);

	kdbus_notify_flush(bus);

	return 0;
}

/**
 * kdbus_conn_has_name() - check if a connection owns a name
 * @conn:		Connection
 * @name:		Well-know name to check for
 *
 * The caller must hold the registry lock of conn->ep->bus.
 *
 * Return: true if the name is currently owned by the connection
 */
bool kdbus_conn_has_name(struct kdbus_conn *conn, const char *name)
{
	struct kdbus_name_entry *e;

	lockdep_assert_held(&conn->ep->bus->name_registry->rwlock);

	list_for_each_entry(e, &conn->names_list, conn_entry)
		if (strcmp(e->name, name) == 0)
			return true;

	return false;
}

struct kdbus_quota {
	uint32_t memory;
	uint16_t msgs;
	uint8_t fds;
};

/**
 * kdbus_conn_quota_inc() - increase quota accounting
 * @c:		connection owning the quota tracking
 * @u:		user to account for (or NULL for kernel accounting)
 * @memory:	size of memory to account for
 * @fds:	number of FDs to account for
 *
 * This call manages the quotas on resource @c. That is, it's used if other
 * users want to use the resources of connection @c, which so far only concerns
 * the receive queue of the destination.
 *
 * This increases the quota-accounting for user @u by @memory bytes and @fds
 * file descriptors. If the user has already reached the quota limits, this call
 * will not do any accounting but return a negative error code indicating the
 * failure.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_conn_quota_inc(struct kdbus_conn *c, struct kdbus_user *u,
			 size_t memory, size_t fds)
{
	struct kdbus_quota *quota;
	size_t available, accounted;
	unsigned int id;

	/*
	 * Pool Layout:
	 * 50% of a pool is always owned by the connection. It is reserved for
	 * kernel queries, handling received messages and other tasks that are
	 * under control of the pool owner. The other 50% of the pool are used
	 * as incoming queue.
	 * As we optionally support user-space based policies, we need fair
	 * allocation schemes. Furthermore, resource utilization should be
	 * maximized, so only minimal resources stay reserved. However, we need
	 * to adapt to a dynamic number of users, as we cannot know how many
	 * users will talk to a connection. Therefore, the current allocations
	 * works like this:
	 * We limit the number of bytes in a destination's pool per sending
	 * user. The space available for a user is 33% of the unused pool space
	 * (whereas the space used by the user itself is also treated as
	 * 'unused'). This way, we favor users coming first, but keep enough
	 * pool space available for any following users. Given that messages are
	 * dequeued in FIFO order, this should balance nicely if the number of
	 * users grows. At the same time, this algorithm guarantees that the
	 * space available to a connection is reduced dynamically, the more
	 * concurrent users talk to a connection.
	 */

	/* per user-accounting is expensive, so we keep state small */
	BUILD_BUG_ON(sizeof(quota->memory) != 4);
	BUILD_BUG_ON(sizeof(quota->msgs) != 2);
	BUILD_BUG_ON(sizeof(quota->fds) != 1);
	BUILD_BUG_ON(KDBUS_CONN_MAX_MSGS > U16_MAX);
	BUILD_BUG_ON(KDBUS_CONN_MAX_FDS_PER_USER > U8_MAX);

	id = u ? u->id : KDBUS_USER_KERNEL_ID;
	if (id >= c->n_quota) {
		unsigned int users;

		users = max(KDBUS_ALIGN8(id) + 8, id);
		quota = krealloc(c->quota, users * sizeof(*quota),
				 GFP_KERNEL | __GFP_ZERO);
		if (!quota)
			return -ENOMEM;

		c->n_quota = users;
		c->quota = quota;
	}

	quota = &c->quota[id];
	kdbus_pool_accounted(c->pool, &available, &accounted);

	/* half the pool is _always_ reserved for the pool owner */
	available /= 2;

	/*
	 * Pool owner slices are un-accounted slices; they can claim more
	 * than 50% of the queue. However, the slice we're dealing with here
	 * belong to the incoming queue, hence they are 'accounted' slices
	 * to which the 50%-limit applies.
	 */
	if (available < accounted)
		return -ENOBUFS;

	/* 1/3 of the remaining space (including your own memory) */
	available = (available - accounted + quota->memory) / 3;

	if (available < quota->memory ||
	    available - quota->memory < memory ||
	    quota->memory + memory > U32_MAX)
		return -ENOBUFS;
	if (quota->msgs >= KDBUS_CONN_MAX_MSGS)
		return -ENOBUFS;
	if (quota->fds + fds < quota->fds ||
	    quota->fds + fds > KDBUS_CONN_MAX_FDS_PER_USER)
		return -EMFILE;

	quota->memory += memory;
	quota->fds += fds;
	++quota->msgs;
	return 0;
}

/**
 * kdbus_conn_quota_dec() - decrease quota accounting
 * @c:		connection owning the quota tracking
 * @u:		user which was accounted for (or NULL for kernel accounting)
 * @memory:	size of memory which was accounted for
 * @fds:	number of FDs which were accounted for
 *
 * This does the reverse of kdbus_conn_quota_inc(). You have to release any
 * accounted resources that you called kdbus_conn_quota_inc() for. However, you
 * must not call kdbus_conn_quota_dec() if the accounting failed (that is,
 * kdbus_conn_quota_inc() failed).
 */
void kdbus_conn_quota_dec(struct kdbus_conn *c, struct kdbus_user *u,
			  size_t memory, size_t fds)
{
	struct kdbus_quota *quota;
	unsigned int id;

	id = u ? u->id : KDBUS_USER_KERNEL_ID;
	if (WARN_ON(id >= c->n_quota))
		return;

	quota = &c->quota[id];

	if (!WARN_ON(quota->msgs == 0))
		--quota->msgs;
	if (!WARN_ON(quota->memory < memory))
		quota->memory -= memory;
	if (!WARN_ON(quota->fds < fds))
		quota->fds -= fds;
}

/**
 * kdbus_conn_lost_message() - handle lost messages
 * @c:		connection that lost a message
 *
 * kdbus is reliable. That means, we try hard to never lose messages. However,
 * memory is limited, so we cannot rely on transmissions to never fail.
 * Therefore, we use quota-limits to let callers know if there unicast message
 * cannot be transmitted to a peer. This works fine for unicasts, but for
 * broadcasts we cannot make the caller handle the transmission failure.
 * Instead, we must let the destination know that it couldn't receive a
 * broadcast.
 * As this is an unlikely scenario, we keep it simple. A single lost-counter
 * remembers the number of lost messages since the last call to RECV. The next
 * message retrieval will notify the connection that it lost messages since the
 * last message retrieval and thus should resync its state.
 */
void kdbus_conn_lost_message(struct kdbus_conn *c)
{
	if (atomic_inc_return(&c->lost_count) == 1)
		wake_up_interruptible(&c->wait);
}

/* Callers should take the conn_dst lock */
static struct kdbus_queue_entry *
kdbus_conn_entry_make(struct kdbus_conn *conn_dst,
		      const struct kdbus_kmsg *kmsg,
		      struct kdbus_user *user)
{
	struct kdbus_queue_entry *entry;

	/* The remote connection was disconnected */
	if (!kdbus_conn_active(conn_dst))
		return ERR_PTR(-ECONNRESET);

	/*
	 * If the connection does not accept file descriptors but the message
	 * has some attached, refuse it.
	 *
	 * If this is a monitor connection, accept the message. In that
	 * case, all file descriptors will be set to -1 at receive time.
	 */
	if (!kdbus_conn_is_monitor(conn_dst) &&
	    !(conn_dst->flags & KDBUS_HELLO_ACCEPT_FD) &&
	    kmsg->res && kmsg->res->fds_count > 0)
		return ERR_PTR(-ECOMM);

	entry = kdbus_queue_entry_new(conn_dst, kmsg, user);
	if (IS_ERR(entry))
		return entry;

	return entry;
}

/*
 * Synchronously responding to a message, allocate a queue entry
 * and attach it to the reply tracking object.
 * The connection's queue will never get to see it.
 */
static int kdbus_conn_entry_sync_attach(struct kdbus_conn *conn_dst,
					const struct kdbus_kmsg *kmsg,
					struct kdbus_reply *reply_wake)
{
	struct kdbus_queue_entry *entry;
	int remote_ret;
	int ret = 0;

	mutex_lock(&reply_wake->reply_dst->lock);

	/*
	 * If we are still waiting then proceed, allocate a queue
	 * entry and attach it to the reply object
	 */
	if (reply_wake->waiting) {
		entry = kdbus_conn_entry_make(conn_dst, kmsg,
					      reply_wake->reply_src->user);
		if (IS_ERR(entry))
			ret = PTR_ERR(entry);
		else
			/* Attach the entry to the reply object */
			reply_wake->queue_entry = entry;
	} else {
		ret = -ECONNRESET;
	}

	/*
	 * Update the reply object and wake up remote peer only
	 * on appropriate return codes
	 *
	 * * -ECOMM: if the replying connection failed with -ECOMM
	 *           then wakeup remote peer with -EREMOTEIO
	 *
	 *           We do this to differenciate between -ECOMM errors
	 *           from the original sender perspective:
	 *           -ECOMM error during the sync send and
	 *           -ECOMM error during the sync reply, this last
	 *           one is rewritten to -EREMOTEIO
	 *
	 * * Wake up on all other return codes.
	 */
	remote_ret = ret;

	if (ret == -ECOMM)
		remote_ret = -EREMOTEIO;

	kdbus_sync_reply_wakeup(reply_wake, remote_ret);
	kdbus_reply_unlink(reply_wake);
	mutex_unlock(&reply_wake->reply_dst->lock);

	return ret;
}

/**
 * kdbus_conn_entry_insert() - enqueue a message into the receiver's pool
 * @conn_src:		The sending connection
 * @conn_dst:		The connection to queue into
 * @kmsg:		The kmsg to queue
 * @reply:		The reply tracker to attach to the queue entry
 *
 * Return: 0 on success. negative error otherwise.
 */
int kdbus_conn_entry_insert(struct kdbus_conn *conn_src,
			    struct kdbus_conn *conn_dst,
			    const struct kdbus_kmsg *kmsg,
			    struct kdbus_reply *reply)
{
	struct kdbus_queue_entry *entry;
	int ret;

	kdbus_conn_lock2(conn_src, conn_dst);

	entry = kdbus_conn_entry_make(conn_dst, kmsg,
				      conn_src ? conn_src->user : NULL);
	if (IS_ERR(entry)) {
		ret = PTR_ERR(entry);
		goto exit_unlock;
	}

	if (reply) {
		kdbus_reply_link(reply);
		if (!reply->sync)
			schedule_delayed_work(&conn_src->work, 0);
	}

	kdbus_queue_entry_enqueue(entry, reply);
	wake_up_interruptible(&conn_dst->wait);

	ret = 0;

exit_unlock:
	kdbus_conn_unlock2(conn_src, conn_dst);
	return ret;
}

static int kdbus_conn_wait_reply(struct kdbus_conn *conn_src,
				 struct kdbus_cmd_send *cmd_send,
				 struct file *ioctl_file,
				 struct file *cancel_fd,
				 struct kdbus_reply *reply_wait,
				 ktime_t expire)
{
	struct kdbus_queue_entry *entry;
	struct poll_wqueues pwq = {};
	int ret;

	if (WARN_ON(!reply_wait))
		return -EIO;

	/*
	 * Block until the reply arrives. reply_wait is left untouched
	 * by the timeout scans that might be conducted for other,
	 * asynchronous replies of conn_src.
	 */

	poll_initwait(&pwq);
	poll_wait(ioctl_file, &conn_src->wait, &pwq.pt);

	for (;;) {
		/*
		 * Any of the following conditions will stop our synchronously
		 * blocking SEND command:
		 *
		 * a) The origin sender closed its connection
		 * b) The remote peer answered, setting reply_wait->waiting = 0
		 * c) The cancel FD was written to
		 * d) A signal was received
		 * e) The specified timeout was reached, and none of the above
		 *    conditions kicked in.
		 */

		/*
		 * We have already acquired an active reference when
		 * entering here, but another thread may call
		 * KDBUS_CMD_BYEBYE which does not acquire an active
		 * reference, therefore kdbus_conn_disconnect() will
		 * not wait for us.
		 */
		if (!kdbus_conn_active(conn_src)) {
			ret = -ECONNRESET;
			break;
		}

		/*
		 * After the replying peer unset the waiting variable
		 * it will wake up us.
		 */
		if (!reply_wait->waiting) {
			ret = reply_wait->err;
			break;
		}

		if (cancel_fd) {
			unsigned int r;

			r = cancel_fd->f_op->poll(cancel_fd, &pwq.pt);
			if (r & POLLIN) {
				ret = -ECANCELED;
				break;
			}
		}

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (!poll_schedule_timeout(&pwq, TASK_INTERRUPTIBLE,
					   &expire, 0)) {
			ret = -ETIMEDOUT;
			break;
		}

		/*
		 * Reset the poll worker func, so the waitqueues are not
		 * added to the poll table again. We just reuse what we've
		 * collected earlier for further iterations.
		 */
		init_poll_funcptr(&pwq.pt, NULL);
	}

	poll_freewait(&pwq);

	if (ret == -EINTR) {
		/*
		 * Interrupted system call. Unref the reply object, and pass
		 * the return value down the chain. Mark the reply as
		 * interrupted, so the cleanup work can remove it, but do not
		 * unlink it from the list. Once the syscall restarts, we'll
		 * pick it up and wait on it again.
		 */
		mutex_lock(&conn_src->lock);
		reply_wait->interrupted = true;
		schedule_delayed_work(&conn_src->work, 0);
		mutex_unlock(&conn_src->lock);

		return -ERESTARTSYS;
	}

	mutex_lock(&conn_src->lock);
	reply_wait->waiting = false;
	entry = reply_wait->queue_entry;
	if (entry) {
		ret = kdbus_queue_entry_install(entry,
						&cmd_send->reply.return_flags,
						true);
		kdbus_pool_slice_publish(entry->slice, &cmd_send->reply.offset,
					 &cmd_send->reply.msg_size);
		kdbus_queue_entry_free(entry);
	}
	kdbus_reply_unlink(reply_wait);
	mutex_unlock(&conn_src->lock);

	return ret;
}

static int kdbus_pin_dst(struct kdbus_bus *bus,
			 struct kdbus_kmsg *kmsg,
			 struct kdbus_name_entry **out_name,
			 struct kdbus_conn **out_dst)
{
	struct kdbus_msg_resources *res = kmsg->res;
	struct kdbus_name_entry *name = NULL;
	struct kdbus_conn *dst = NULL;
	struct kdbus_msg *msg = &kmsg->msg;
	int ret;

	if (WARN_ON(!res))
		return -EINVAL;

	lockdep_assert_held(&bus->name_registry->rwlock);

	if (!res->dst_name) {
		dst = kdbus_bus_find_conn_by_id(bus, msg->dst_id);
		if (!dst)
			return -ENXIO;

		if (!kdbus_conn_is_ordinary(dst)) {
			ret = -ENXIO;
			goto error;
		}
	} else {
		name = kdbus_name_lookup_unlocked(bus->name_registry,
						  res->dst_name);
		if (!name)
			return -ESRCH;

		/*
		 * If both a name and a connection ID are given as destination
		 * of a message, check that the currently owning connection of
		 * the name matches the specified ID.
		 * This way, we allow userspace to send the message to a
		 * specific connection by ID only if the connection currently
		 * owns the given name.
		 */
		if (msg->dst_id != KDBUS_DST_ID_NAME &&
		    msg->dst_id != name->conn->id)
			return -EREMCHG;

		if (!name->conn && name->activator)
			dst = kdbus_conn_ref(name->activator);
		else
			dst = kdbus_conn_ref(name->conn);

		if ((msg->flags & KDBUS_MSG_NO_AUTO_START) &&
		    kdbus_conn_is_activator(dst)) {
			ret = -EADDRNOTAVAIL;
			goto error;
		}

		/*
		 * Record the sequence number of the registered name; it will
		 * be passed on to the queue, in case messages addressed to a
		 * name need to be moved from or to an activator.
		 */
		kmsg->dst_name_id = name->name_id;
	}

	*out_name = name;
	*out_dst = dst;
	return 0;

error:
	kdbus_conn_unref(dst);
	return ret;
}

static int kdbus_conn_reply(struct kdbus_conn *src, struct kdbus_kmsg *kmsg)
{
	struct kdbus_name_entry *name = NULL;
	struct kdbus_reply *reply, *wake = NULL;
	struct kdbus_conn *dst = NULL;
	struct kdbus_bus *bus = src->ep->bus;
	u64 attach;
	int ret;

	if (WARN_ON(kmsg->msg.dst_id == KDBUS_DST_ID_BROADCAST) ||
	    WARN_ON(kmsg->msg.flags & KDBUS_MSG_EXPECT_REPLY) ||
	    WARN_ON(kmsg->msg.flags & KDBUS_MSG_SIGNAL))
		return -EINVAL;

	/* name-registry must be locked for lookup *and* collecting data */
	down_read(&bus->name_registry->rwlock);

	/* find and pin destination */

	ret = kdbus_pin_dst(bus, kmsg, &name, &dst);
	if (ret < 0)
		goto exit;

	mutex_lock(&dst->lock);
	reply = kdbus_reply_find(src, dst, kmsg->msg.cookie_reply);
	if (reply) {
		if (reply->sync)
			wake = kdbus_reply_ref(reply);
		kdbus_reply_unlink(reply);
	}
	mutex_unlock(&dst->lock);

	if (!reply) {
		ret = -EPERM;
		goto exit;
	}

	/* attach metadata */

	attach = kdbus_meta_calc_attach_flags(src, dst);

	if (!src->faked_meta) {
		ret = kdbus_meta_proc_collect(kmsg->proc_meta, attach);
		if (ret < 0)
			goto exit;
	}

	ret = kdbus_meta_conn_collect(kmsg->conn_meta, kmsg, src, attach);
	if (ret < 0)
		goto exit;

	/* send message */

	kdbus_bus_eavesdrop(bus, src, kmsg);

	if (wake)
		ret = kdbus_conn_entry_sync_attach(dst, kmsg, wake);
	else
		ret = kdbus_conn_entry_insert(src, dst, kmsg, NULL);

exit:
	up_read(&bus->name_registry->rwlock);
	kdbus_reply_unref(wake);
	kdbus_conn_unref(dst);
	return ret;
}

static struct kdbus_reply *kdbus_conn_call(struct kdbus_conn *src,
					   struct kdbus_kmsg *kmsg,
					   ktime_t exp)
{
	struct kdbus_name_entry *name = NULL;
	struct kdbus_reply *wait = NULL;
	struct kdbus_conn *dst = NULL;
	struct kdbus_bus *bus = src->ep->bus;
	u64 attach;
	int ret;

	if (WARN_ON(kmsg->msg.dst_id == KDBUS_DST_ID_BROADCAST) ||
	    WARN_ON(kmsg->msg.flags & KDBUS_MSG_SIGNAL) ||
	    WARN_ON(!(kmsg->msg.flags & KDBUS_MSG_EXPECT_REPLY)))
		return ERR_PTR(-EINVAL);

	/* resume previous wait-context, if available */

	mutex_lock(&src->lock);
	wait = kdbus_reply_find(NULL, src, kmsg->msg.cookie);
	if (wait) {
		if (wait->interrupted) {
			kdbus_reply_ref(wait);
			wait->interrupted = false;
		} else {
			wait = NULL;
		}
	}
	mutex_unlock(&src->lock);

	if (wait)
		return wait;

	if (ktime_compare(ktime_get(), exp) >= 0)
		return ERR_PTR(-ETIMEDOUT);

	/* name-registry must be locked for lookup *and* collecting data */
	down_read(&bus->name_registry->rwlock);

	/* find and pin destination */

	ret = kdbus_pin_dst(bus, kmsg, &name, &dst);
	if (ret < 0)
		goto exit;

	if (!kdbus_conn_policy_talk(src, current_cred(), dst)) {
		ret = -EPERM;
		goto exit;
	}

	wait = kdbus_reply_new(dst, src, &kmsg->msg, name, true);
	if (IS_ERR(wait)) {
		ret = PTR_ERR(wait);
		wait = NULL;
		goto exit;
	}

	/* attach metadata */

	attach = kdbus_meta_calc_attach_flags(src, dst);

	if (!src->faked_meta) {
		ret = kdbus_meta_proc_collect(kmsg->proc_meta, attach);
		if (ret < 0)
			goto exit;
	}

	ret = kdbus_meta_conn_collect(kmsg->conn_meta, kmsg, src, attach);
	if (ret < 0)
		goto exit;

	/* send message */

	kdbus_bus_eavesdrop(bus, src, kmsg);

	ret = kdbus_conn_entry_insert(src, dst, kmsg, wait);
	if (ret < 0)
		goto exit;

	ret = 0;

exit:
	up_read(&bus->name_registry->rwlock);
	if (ret < 0) {
		kdbus_reply_unref(wait);
		wait = ERR_PTR(ret);
	}
	kdbus_conn_unref(dst);
	return wait;
}

static int kdbus_conn_unicast(struct kdbus_conn *src, struct kdbus_kmsg *kmsg)
{
	struct kdbus_name_entry *name = NULL;
	struct kdbus_reply *wait = NULL;
	struct kdbus_conn *dst = NULL;
	struct kdbus_bus *bus = src->ep->bus;
	bool is_signal = (kmsg->msg.flags & KDBUS_MSG_SIGNAL);
	u64 attach;
	int ret = 0;

	if (WARN_ON(kmsg->msg.dst_id == KDBUS_DST_ID_BROADCAST) ||
	    WARN_ON(!(kmsg->msg.flags & KDBUS_MSG_EXPECT_REPLY) &&
		    kmsg->msg.cookie_reply != 0))
		return -EINVAL;

	/* name-registry must be locked for lookup *and* collecting data */
	down_read(&bus->name_registry->rwlock);

	/* find and pin destination */

	ret = kdbus_pin_dst(bus, kmsg, &name, &dst);
	if (ret < 0)
		goto exit;

	if (is_signal) {
		/* like broadcasts we eavesdrop even if the msg is dropped */
		kdbus_bus_eavesdrop(bus, src, kmsg);

		/* drop silently if peer is not interested or not privileged */
		if (!kdbus_match_db_match_kmsg(dst->match_db, src, kmsg) ||
		    !kdbus_conn_policy_talk(dst, NULL, src))
			goto exit;
	} else if (!kdbus_conn_policy_talk(src, current_cred(), dst)) {
		ret = -EPERM;
		goto exit;
	} else if (kmsg->msg.flags & KDBUS_MSG_EXPECT_REPLY) {
		wait = kdbus_reply_new(dst, src, &kmsg->msg, name, false);
		if (IS_ERR(wait)) {
			ret = PTR_ERR(wait);
			wait = NULL;
			goto exit;
		}
	}

	/* attach metadata */

	attach = kdbus_meta_calc_attach_flags(src, dst);

	if (!src->faked_meta) {
		ret = kdbus_meta_proc_collect(kmsg->proc_meta, attach);
		if (ret < 0 && !is_signal)
			goto exit;
	}

	ret = kdbus_meta_conn_collect(kmsg->conn_meta, kmsg, src, attach);
	if (ret < 0 && !is_signal)
		goto exit;

	/* send message */

	if (!is_signal)
		kdbus_bus_eavesdrop(bus, src, kmsg);

	ret = kdbus_conn_entry_insert(src, dst, kmsg, wait);
	if (ret < 0 && !is_signal)
		goto exit;

	/* signals are treated like broadcasts, recv-errors are ignored */
	ret = 0;

exit:
	up_read(&bus->name_registry->rwlock);
	kdbus_reply_unref(wait);
	kdbus_conn_unref(dst);
	return ret;
}

/**
 * kdbus_conn_move_messages() - move messages from one connection to another
 * @conn_dst:		Connection to copy to
 * @conn_src:		Connection to copy from
 * @name_id:		Filter for the sequence number of the registered
 *			name, 0 means no filtering.
 *
 * Move all messages from one connection to another. This is used when
 * an implementer connection is taking over/giving back a well-known name
 * from/to an activator connection.
 */
void kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			      struct kdbus_conn *conn_src,
			      u64 name_id)
{
	struct kdbus_queue_entry *e, *e_tmp;
	struct kdbus_reply *r, *r_tmp;
	struct kdbus_bus *bus;
	struct kdbus_conn *c;
	LIST_HEAD(msg_list);
	int i, ret = 0;

	if (WARN_ON(conn_src == conn_dst))
		return;

	bus = conn_src->ep->bus;

	/* lock order: domain -> bus -> ep -> names -> conn */
	down_read(&bus->conn_rwlock);
	hash_for_each(bus->conn_hash, i, c, hentry) {
		if (c == conn_src || c == conn_dst)
			continue;

		mutex_lock(&c->lock);
		list_for_each_entry_safe(r, r_tmp, &c->reply_list, entry) {
			if (r->reply_src != conn_src)
				continue;

			/* filter messages for a specific name */
			if (name_id > 0 && r->name_id != name_id)
				continue;

			kdbus_conn_unref(r->reply_src);
			r->reply_src = kdbus_conn_ref(conn_dst);
		}
		mutex_unlock(&c->lock);
	}
	up_read(&bus->conn_rwlock);

	kdbus_conn_lock2(conn_src, conn_dst);
	list_for_each_entry_safe(e, e_tmp, &conn_src->queue.msg_list, entry) {
		/* filter messages for a specific name */
		if (name_id > 0 && e->dst_name_id != name_id)
			continue;

		if (!(conn_dst->flags & KDBUS_HELLO_ACCEPT_FD) &&
		    e->msg_res && e->msg_res->fds_count > 0) {
			kdbus_conn_lost_message(conn_dst);
			kdbus_queue_entry_free(e);
			continue;
		}

		ret = kdbus_queue_entry_move(e, conn_dst);
		if (ret < 0) {
			kdbus_conn_lost_message(conn_dst);
			kdbus_queue_entry_free(e);
			continue;
		}
	}
	kdbus_conn_unlock2(conn_src, conn_dst);

	/* wake up poll() */
	wake_up_interruptible(&conn_dst->wait);
}

/* query the policy-database for all names of @whom */
static bool kdbus_conn_policy_query_all(struct kdbus_conn *conn,
					const struct cred *conn_creds,
					struct kdbus_policy_db *db,
					struct kdbus_conn *whom,
					unsigned int access)
{
	struct kdbus_name_entry *ne;
	bool pass = false;
	int res;

	lockdep_assert_held(&conn->ep->bus->name_registry->rwlock);

	down_read(&db->entries_rwlock);
	mutex_lock(&whom->lock);

	list_for_each_entry(ne, &whom->names_list, conn_entry) {
		res = kdbus_policy_query_unlocked(db, conn_creds ? : conn->cred,
						  ne->name,
						  kdbus_strhash(ne->name));
		if (res >= (int)access) {
			pass = true;
			break;
		}
	}

	mutex_unlock(&whom->lock);
	up_read(&db->entries_rwlock);

	return pass;
}

/**
 * kdbus_conn_policy_own_name() - verify a connection can own the given name
 * @conn:		Connection
 * @conn_creds:		Credentials of @conn to use for policy check
 * @name:		Name
 *
 * This verifies that @conn is allowed to acquire the well-known name @name.
 *
 * Return: true if allowed, false if not.
 */
bool kdbus_conn_policy_own_name(struct kdbus_conn *conn,
				const struct cred *conn_creds,
				const char *name)
{
	unsigned int hash = kdbus_strhash(name);
	int res;

	if (!conn_creds)
		conn_creds = conn->cred;

	if (conn->ep->user) {
		res = kdbus_policy_query(&conn->ep->policy_db, conn_creds,
					 name, hash);
		if (res < KDBUS_POLICY_OWN)
			return false;
	}

	if (conn->privileged)
		return true;

	res = kdbus_policy_query(&conn->ep->bus->policy_db, conn_creds,
				 name, hash);
	return res >= KDBUS_POLICY_OWN;
}

/**
 * kdbus_conn_policy_talk() - verify a connection can talk to a given peer
 * @conn:		Connection that tries to talk
 * @conn_creds:		Credentials of @conn to use for policy check
 * @to:			Connection that is talked to
 *
 * This verifies that @conn is allowed to talk to @to.
 *
 * Return: true if allowed, false if not.
 */
bool kdbus_conn_policy_talk(struct kdbus_conn *conn,
			    const struct cred *conn_creds,
			    struct kdbus_conn *to)
{
	if (!conn_creds)
		conn_creds = conn->cred;

	if (conn->ep->user &&
	    !kdbus_conn_policy_query_all(conn, conn_creds, &conn->ep->policy_db,
					 to, KDBUS_POLICY_TALK))
		return false;

	if (conn->privileged)
		return true;
	if (uid_eq(conn_creds->euid, to->cred->uid))
		return true;

	return kdbus_conn_policy_query_all(conn, conn_creds,
					   &conn->ep->bus->policy_db, to,
					   KDBUS_POLICY_TALK);
}

/**
 * kdbus_conn_policy_see_name_unlocked() - verify a connection can see a given
 *					   name
 * @conn:		Connection
 * @conn_creds:		Credentials of @conn to use for policy check
 * @name:		Name
 *
 * This verifies that @conn is allowed to see the well-known name @name. Caller
 * must hold policy-lock.
 *
 * Return: true if allowed, false if not.
 */
bool kdbus_conn_policy_see_name_unlocked(struct kdbus_conn *conn,
					 const struct cred *conn_creds,
					 const char *name)
{
	int res;

	/*
	 * By default, all names are visible on a bus. SEE policies can only be
	 * installed on custom endpoints, where by default no name is visible.
	 */
	if (!conn->ep->user)
		return true;

	res = kdbus_policy_query_unlocked(&conn->ep->policy_db,
					  conn_creds ? : conn->cred,
					  name, kdbus_strhash(name));
	return res >= KDBUS_POLICY_SEE;
}

static bool kdbus_conn_policy_see_name(struct kdbus_conn *conn,
				       const struct cred *conn_creds,
				       const char *name)
{
	bool res;

	down_read(&conn->ep->policy_db.entries_rwlock);
	res = kdbus_conn_policy_see_name_unlocked(conn, conn_creds, name);
	up_read(&conn->ep->policy_db.entries_rwlock);

	return res;
}

static bool kdbus_conn_policy_see(struct kdbus_conn *conn,
				  const struct cred *conn_creds,
				  struct kdbus_conn *whom)
{
	/*
	 * By default, all names are visible on a bus, so a connection can
	 * always see other connections. SEE policies can only be installed on
	 * custom endpoints, where by default no name is visible and we hide
	 * peers from each other, unless you see at least _one_ name of the
	 * peer.
	 */
	return !conn->ep->user ||
	       kdbus_conn_policy_query_all(conn, conn_creds,
					   &conn->ep->policy_db, whom,
					   KDBUS_POLICY_SEE);
}

/**
 * kdbus_conn_policy_see_notification() - verify a connection is allowed to
 *					  receive a given kernel notification
 * @conn:		Connection
 * @conn_creds:		Credentials of @conn to use for policy check
 * @kmsg:		The message carrying the notification
 *
 * This checks whether @conn is allowed to see the kernel notification @kmsg.
 *
 * Return: true if allowed, false if not.
 */
bool kdbus_conn_policy_see_notification(struct kdbus_conn *conn,
					const struct cred *conn_creds,
					const struct kdbus_kmsg *kmsg)
{
	if (WARN_ON(kmsg->msg.src_id != KDBUS_SRC_ID_KERNEL))
		return false;

	/*
	 * Depending on the notification type, broadcasted kernel notifications
	 * have to be filtered:
	 *
	 * KDBUS_ITEM_NAME_{ADD,REMOVE,CHANGE}: This notification is forwarded
	 *     to a peer if, and only if, that peer can see the name this
	 *     notification is for.
	 *
	 * KDBUS_ITEM_ID_{ADD,REMOVE}: As new peers cannot have names, and all
	 *     names are dropped before a peer is removed, those notifications
	 *     cannot be seen on custom endpoints. Thus, we only pass them
	 *     through on default endpoints.
	 */

	switch (kmsg->notify_type) {
	case KDBUS_ITEM_NAME_ADD:
	case KDBUS_ITEM_NAME_REMOVE:
	case KDBUS_ITEM_NAME_CHANGE:
		return kdbus_conn_policy_see_name(conn, conn_creds,
						  kmsg->notify_name);

	case KDBUS_ITEM_ID_ADD:
	case KDBUS_ITEM_ID_REMOVE:
		return !conn->ep->user;

	default:
		WARN(1, "Invalid type for notification broadcast: %llu\n",
		     (unsigned long long)kmsg->notify_type);
		return false;
	}
}

/**
 * kdbus_cmd_hello() - handle KDBUS_CMD_HELLO
 * @ep:			Endpoint to operate on
 * @privileged:		Whether the caller is privileged
 * @argp:		Command payload
 *
 * Return: Newly created connection on success, ERR_PTR on failure.
 */
struct kdbus_conn *kdbus_cmd_hello(struct kdbus_ep *ep, bool privileged,
				   void __user *argp)
{
	struct kdbus_cmd_hello *cmd;
	struct kdbus_conn *c = NULL;
	const char *item_name;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_NAME },
		{ .type = KDBUS_ITEM_CREDS },
		{ .type = KDBUS_ITEM_PIDS },
		{ .type = KDBUS_ITEM_SECLABEL },
		{ .type = KDBUS_ITEM_CONN_DESCRIPTION },
		{ .type = KDBUS_ITEM_POLICY_ACCESS, .multiple = true },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_HELLO_ACCEPT_FD |
				 KDBUS_HELLO_ACTIVATOR |
				 KDBUS_HELLO_POLICY_HOLDER |
				 KDBUS_HELLO_MONITOR,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0)
		return NULL;

	item_name = argv[1].item ? argv[1].item->str : NULL;

	c = kdbus_conn_new(ep, privileged, cmd, item_name,
			   argv[2].item ? &argv[2].item->creds : NULL,
			   argv[3].item ? &argv[3].item->pids : NULL,
			   argv[4].item ? argv[4].item->str : NULL,
			   argv[5].item ? argv[5].item->str : NULL);
	if (IS_ERR(c)) {
		ret = PTR_ERR(c);
		c = NULL;
		goto exit;
	}

	ret = kdbus_conn_connect(c, item_name);
	if (ret < 0)
		goto exit;

	if (kdbus_conn_is_activator(c) || kdbus_conn_is_policy_holder(c)) {
		ret = kdbus_conn_acquire(c);
		if (ret < 0)
			goto exit;

		ret = kdbus_policy_set(&c->ep->bus->policy_db, args.items,
				       args.items_size, 1,
				       kdbus_conn_is_policy_holder(c), c);
		kdbus_conn_release(c);
		if (ret < 0)
			goto exit;
	}

	if (copy_to_user(argp, cmd, sizeof(*cmd)))
		ret = -EFAULT;

exit:
	ret = kdbus_args_clear(&args, ret);
	if (ret < 0) {
		if (c) {
			kdbus_conn_disconnect(c, false);
			kdbus_conn_unref(c);
		}
		return ERR_PTR(ret);
	}
	return c;
}

/**
 * kdbus_cmd_byebye_unlocked() - handle KDBUS_CMD_BYEBYE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * The caller must not hold any active reference to @conn or this will deadlock.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_byebye_unlocked(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_cmd *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
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

	ret = kdbus_conn_disconnect(conn, true);
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_conn_info() - handle KDBUS_CMD_CONN_INFO
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_conn_info(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_meta_conn *conn_meta = NULL;
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_name_entry *entry = NULL;
	struct kdbus_conn *owner_conn = NULL;
	struct kdbus_info info = {};
	struct kdbus_cmd_info *cmd;
	struct kdbus_bus *bus = conn->ep->bus;
	struct kvec kvec;
	size_t meta_size;
	const char *name;
	u64 attach_flags;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_NAME },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	/* registry must be held throughout lookup *and* collecting data */
	down_read(&bus->name_registry->rwlock);

	ret = kdbus_sanitize_attach_flags(cmd->attach_flags, &attach_flags);
	if (ret < 0)
		goto exit;

	name = argv[1].item ? argv[1].item->str : NULL;

	if (name) {
		entry = kdbus_name_lookup_unlocked(bus->name_registry, name);
		if (!entry || !entry->conn ||
		    !kdbus_conn_policy_see_name(conn, current_cred(), name) ||
		    (cmd->id != 0 && entry->conn->id != cmd->id)) {
			/* pretend a name doesn't exist if you cannot see it */
			ret = -ESRCH;
			goto exit;
		}

		owner_conn = kdbus_conn_ref(entry->conn);
	} else if (cmd->id > 0) {
		owner_conn = kdbus_bus_find_conn_by_id(bus, cmd->id);
		if (!owner_conn || !kdbus_conn_policy_see(conn, current_cred(),
							  owner_conn)) {
			/* pretend an id doesn't exist if you cannot see it */
			ret = -ENXIO;
			goto exit;
		}
	} else {
		ret = -EINVAL;
		goto exit;
	}

	info.id = owner_conn->id;
	info.flags = owner_conn->flags;
	kdbus_kvec_set(&kvec, &info, sizeof(info), &info.size);

	attach_flags &= atomic64_read(&owner_conn->attach_flags_send);

	conn_meta = kdbus_meta_conn_new();
	if (IS_ERR(conn_meta)) {
		ret = PTR_ERR(conn_meta);
		conn_meta = NULL;
		goto exit;
	}

	ret = kdbus_meta_conn_collect(conn_meta, NULL, owner_conn,
				      attach_flags);
	if (ret < 0)
		goto exit;

	ret = kdbus_meta_export_prepare(owner_conn->meta, conn_meta,
					&attach_flags, &meta_size);
	if (ret < 0)
		goto exit;

	slice = kdbus_pool_slice_alloc(conn->pool,
				       info.size + meta_size, false);
	if (IS_ERR(slice)) {
		ret = PTR_ERR(slice);
		slice = NULL;
		goto exit;
	}

	ret = kdbus_meta_export(owner_conn->meta, conn_meta, attach_flags,
				slice, sizeof(info), &meta_size);
	if (ret < 0)
		goto exit;

	info.size += meta_size;

	ret = kdbus_pool_slice_copy_kvec(slice, 0, &kvec, 1, sizeof(info));
	if (ret < 0)
		goto exit;

	kdbus_pool_slice_publish(slice, &cmd->offset, &cmd->info_size);

	if (kdbus_member_set_user(&cmd->offset, argp, typeof(*cmd), offset) ||
	    kdbus_member_set_user(&cmd->info_size, argp,
				  typeof(*cmd), info_size)) {
		ret = -EFAULT;
		goto exit;
	}

	ret = 0;

exit:
	up_read(&bus->name_registry->rwlock);
	kdbus_pool_slice_release(slice);
	kdbus_meta_conn_unref(conn_meta);
	kdbus_conn_unref(owner_conn);
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_update() - handle KDBUS_CMD_UPDATE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_update(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_bus *bus = conn->ep->bus;
	struct kdbus_item *item_policy;
	u64 *item_attach_send = NULL;
	u64 *item_attach_recv = NULL;
	struct kdbus_cmd *cmd;
	u64 attach_send;
	u64 attach_recv;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_ATTACH_FLAGS_SEND },
		{ .type = KDBUS_ITEM_ATTACH_FLAGS_RECV },
		{ .type = KDBUS_ITEM_NAME, .multiple = true },
		{ .type = KDBUS_ITEM_POLICY_ACCESS, .multiple = true },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	item_attach_send = argv[1].item ? &argv[1].item->data64[0] : NULL;
	item_attach_recv = argv[2].item ? &argv[2].item->data64[0] : NULL;
	item_policy = argv[3].item ? : argv[4].item;

	if (item_attach_send) {
		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			goto exit;
		}

		ret = kdbus_sanitize_attach_flags(*item_attach_send,
						  &attach_send);
		if (ret < 0)
			goto exit;

		if (bus->attach_flags_req & ~attach_send) {
			ret = -EINVAL;
			goto exit;
		}
	}

	if (item_attach_recv) {
		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn) &&
		    !kdbus_conn_is_activator(conn)) {
			ret = -EOPNOTSUPP;
			goto exit;
		}

		ret = kdbus_sanitize_attach_flags(*item_attach_recv,
						  &attach_recv);
		if (ret < 0)
			goto exit;
	}

	if (item_policy && !kdbus_conn_is_policy_holder(conn)) {
		ret = -EOPNOTSUPP;
		goto exit;
	}

	/* now that we verified the input, update the connection */

	if (item_policy) {
		ret = kdbus_policy_set(&conn->ep->bus->policy_db, cmd->items,
				       KDBUS_ITEMS_SIZE(cmd, items),
				       1, true, conn);
		if (ret < 0)
			goto exit;
	}

	if (item_attach_send)
		atomic64_set(&conn->attach_flags_send, attach_send);

	if (item_attach_recv)
		atomic64_set(&conn->attach_flags_recv, attach_recv);

exit:
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_send() - handle KDBUS_CMD_SEND
 * @conn:		connection to operate on
 * @f:			file this command was called on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_send(struct kdbus_conn *conn, struct file *f, void __user *argp)
{
	struct kdbus_cmd_send *cmd;
	struct kdbus_kmsg *kmsg = NULL;
	struct file *cancel_fd = NULL;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_CANCEL_FD },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_SEND_SYNC_REPLY,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	cmd->reply.return_flags = 0;
	kdbus_pool_publish_empty(conn->pool, &cmd->reply.offset,
				 &cmd->reply.msg_size);

	if (argv[1].item) {
		cancel_fd = fget(argv[1].item->fds[0]);
		if (IS_ERR(cancel_fd)) {
			ret = PTR_ERR(cancel_fd);
			cancel_fd = NULL;
			goto exit;
		}

		if (!cancel_fd->f_op->poll) {
			ret = -EINVAL;
			goto exit;
		}
	}

	kmsg = kdbus_kmsg_new_from_cmd(conn, cmd);
	if (IS_ERR(kmsg)) {
		ret = PTR_ERR(kmsg);
		kmsg = NULL;
		goto exit;
	}

	if (kmsg->msg.dst_id == KDBUS_DST_ID_BROADCAST) {
		down_read(&conn->ep->bus->name_registry->rwlock);
		kdbus_bus_broadcast(conn->ep->bus, conn, kmsg);
		up_read(&conn->ep->bus->name_registry->rwlock);
	} else if (cmd->flags & KDBUS_SEND_SYNC_REPLY) {
		struct kdbus_reply *r;
		ktime_t exp;

		exp = ns_to_ktime(kmsg->msg.timeout_ns);
		r = kdbus_conn_call(conn, kmsg, exp);
		if (IS_ERR(r)) {
			ret = PTR_ERR(r);
			goto exit;
		}

		ret = kdbus_conn_wait_reply(conn, cmd, f, cancel_fd, r, exp);
		kdbus_reply_unref(r);
		if (ret < 0)
			goto exit;
	} else if ((kmsg->msg.flags & KDBUS_MSG_EXPECT_REPLY) ||
		   kmsg->msg.cookie_reply == 0) {
		ret = kdbus_conn_unicast(conn, kmsg);
		if (ret < 0)
			goto exit;
	} else {
		ret = kdbus_conn_reply(conn, kmsg);
		if (ret < 0)
			goto exit;
	}

	if (kdbus_member_set_user(&cmd->reply, argp, typeof(*cmd), reply))
		ret = -EFAULT;

exit:
	if (cancel_fd)
		fput(cancel_fd);
	kdbus_kmsg_free(kmsg);
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_recv() - handle KDBUS_CMD_RECV
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_recv(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_queue_entry *entry;
	struct kdbus_cmd_recv *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_RECV_PEEK |
				 KDBUS_RECV_DROP |
				 KDBUS_RECV_USE_PRIORITY,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn) &&
	    !kdbus_conn_is_monitor(conn) &&
	    !kdbus_conn_is_activator(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	cmd->dropped_msgs = 0;
	cmd->msg.return_flags = 0;
	kdbus_pool_publish_empty(conn->pool, &cmd->msg.offset,
				 &cmd->msg.msg_size);

	/* DROP+priority is not realiably, so prevent it */
	if ((cmd->flags & KDBUS_RECV_DROP) &&
	    (cmd->flags & KDBUS_RECV_USE_PRIORITY)) {
		ret = -EINVAL;
		goto exit;
	}

	mutex_lock(&conn->lock);

	entry = kdbus_queue_peek(&conn->queue, cmd->priority,
				 cmd->flags & KDBUS_RECV_USE_PRIORITY);
	if (!entry) {
		mutex_unlock(&conn->lock);
		ret = -EAGAIN;
	} else if (cmd->flags & KDBUS_RECV_DROP) {
		struct kdbus_reply *reply = kdbus_reply_ref(entry->reply);

		kdbus_queue_entry_free(entry);

		mutex_unlock(&conn->lock);

		if (reply) {
			mutex_lock(&reply->reply_dst->lock);
			if (!list_empty(&reply->entry)) {
				kdbus_reply_unlink(reply);
				if (reply->sync)
					kdbus_sync_reply_wakeup(reply, -EPIPE);
				else
					kdbus_notify_reply_dead(conn->ep->bus,
							reply->reply_dst->id,
							reply->cookie);
			}
			mutex_unlock(&reply->reply_dst->lock);
			kdbus_notify_flush(conn->ep->bus);
		}

		kdbus_reply_unref(reply);
	} else {
		bool install_fds;

		/*
		 * PEEK just returns the location of the next message. Do not
		 * install FDs nor memfds nor anything else. The only
		 * information of interest should be the message header and
		 * metadata. Any FD numbers in the payload is undefined for
		 * PEEK'ed messages.
		 * Also make sure to never install fds into a connection that
		 * has refused to receive any. Ordinary connections will not get
		 * messages with FDs queued (the receiver will get -ECOMM), but
		 * eavesdroppers might.
		 */
		install_fds = (conn->flags & KDBUS_HELLO_ACCEPT_FD) &&
			      !(cmd->flags & KDBUS_RECV_PEEK);

		ret = kdbus_queue_entry_install(entry,
						&cmd->msg.return_flags,
						install_fds);
		if (ret < 0) {
			mutex_unlock(&conn->lock);
			goto exit;
		}

		kdbus_pool_slice_publish(entry->slice, &cmd->msg.offset,
					 &cmd->msg.msg_size);

		if (!(cmd->flags & KDBUS_RECV_PEEK))
			kdbus_queue_entry_free(entry);

		mutex_unlock(&conn->lock);
	}

	cmd->dropped_msgs = atomic_xchg(&conn->lost_count, 0);
	if (cmd->dropped_msgs > 0)
		cmd->return_flags |= KDBUS_RECV_RETURN_DROPPED_MSGS;

	if (kdbus_member_set_user(&cmd->msg, argp, typeof(*cmd), msg) ||
	    kdbus_member_set_user(&cmd->dropped_msgs, argp, typeof(*cmd),
				  dropped_msgs))
		ret = -EFAULT;

exit:
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_free() - handle KDBUS_CMD_FREE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_free(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_cmd_free *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn) &&
	    !kdbus_conn_is_monitor(conn) &&
	    !kdbus_conn_is_activator(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	ret = kdbus_pool_release_offset(conn->pool, cmd->offset);

	return kdbus_args_clear(&args, ret);
}
