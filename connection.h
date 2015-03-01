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

#ifndef __KDBUS_CONNECTION_H
#define __KDBUS_CONNECTION_H

#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/path.h>

#include "limits.h"
#include "metadata.h"
#include "pool.h"
#include "queue.h"
#include "util.h"

#define KDBUS_HELLO_SPECIAL_CONN	(KDBUS_HELLO_ACTIVATOR | \
					 KDBUS_HELLO_POLICY_HOLDER | \
					 KDBUS_HELLO_MONITOR)

struct kdbus_quota;
struct kdbus_kmsg;

/**
 * struct kdbus_conn - connection to a bus
 * @kref:		Reference count
 * @active:		Active references to the connection
 * @id:			Connection ID
 * @flags:		KDBUS_HELLO_* flags
 * @attach_flags_send:	KDBUS_ATTACH_* flags for sending
 * @attach_flags_recv:	KDBUS_ATTACH_* flags for receiving
 * @description:	Human-readable connection description, used for
 *			debugging. This field is only set when the
 *			connection is created.
 * @ep:			The endpoint this connection belongs to
 * @lock:		Connection data lock
 * @hentry:		Entry in ID <-> connection map
 * @ep_entry:		Entry in endpoint
 * @monitor_entry:	Entry in monitor, if the connection is a monitor
 * @reply_list:		List of connections this connection should
 *			reply to
 * @work:		Delayed work to handle timeouts
 *			activator for
 * @match_db:		Subscription filter to broadcast messages
 * @meta:		Active connection creator's metadata/credentials,
 *			either from the handle or from HELLO
 * @pool:		The user's buffer to receive messages
 * @user:		Owner of the connection
 * @cred:		The credentials of the connection at creation time
 * @name_count:		Number of owned well-known names
 * @request_count:	Number of pending requests issued by this
 *			connection that are waiting for replies from
 *			other peers
 * @lost_count:		Number of lost broadcast messages
 * @wait:		Wake up this endpoint
 * @queue:		The message queue associated with this connection
 * @quota:		Array of per-user quota indexed by user->id
 * @n_quota:		Number of elements in quota array
 * @activator_of:	Well-known name entry this connection acts as an
 * @names_list:		List of well-known names
 * @names_queue_list:	Well-known names this connection waits for
 * @privileged:		Whether this connection is privileged on the bus
 * @faked_meta:		Whether the metadata was faked on HELLO
 */
struct kdbus_conn {
	struct kref kref;
	atomic_t active;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
	u64 id;
	u64 flags;
	atomic64_t attach_flags_send;
	atomic64_t attach_flags_recv;
	const char *description;
	struct kdbus_ep *ep;
	struct mutex lock;
	struct hlist_node hentry;
	struct list_head ep_entry;
	struct list_head monitor_entry;
	struct list_head reply_list;
	struct delayed_work work;
	struct kdbus_match_db *match_db;
	struct kdbus_meta_proc *meta;
	struct kdbus_pool *pool;
	struct kdbus_user *user;
	const struct cred *cred;
	atomic_t name_count;
	atomic_t request_count;
	atomic_t lost_count;
	wait_queue_head_t wait;
	struct kdbus_queue queue;

	struct kdbus_quota *quota;
	unsigned int n_quota;

	/* protected by registry->rwlock */
	struct kdbus_name_entry *activator_of;
	struct list_head names_list;
	struct list_head names_queue_list;

	bool privileged:1;
	bool faked_meta:1;
};

struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn);
struct kdbus_conn *kdbus_conn_unref(struct kdbus_conn *conn);
bool kdbus_conn_active(const struct kdbus_conn *conn);
int kdbus_conn_acquire(struct kdbus_conn *conn);
void kdbus_conn_release(struct kdbus_conn *conn);
int kdbus_conn_disconnect(struct kdbus_conn *conn, bool ensure_queue_empty);
bool kdbus_conn_has_name(struct kdbus_conn *conn, const char *name);
int kdbus_conn_quota_inc(struct kdbus_conn *c, struct kdbus_user *u,
			 size_t memory, size_t fds);
void kdbus_conn_quota_dec(struct kdbus_conn *c, struct kdbus_user *u,
			  size_t memory, size_t fds);
void kdbus_conn_lost_message(struct kdbus_conn *c);
int kdbus_conn_entry_insert(struct kdbus_conn *conn_src,
			    struct kdbus_conn *conn_dst,
			    const struct kdbus_kmsg *kmsg,
			    struct kdbus_reply *reply);
void kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			      struct kdbus_conn *conn_src,
			      u64 name_id);

/* policy */
bool kdbus_conn_policy_own_name(struct kdbus_conn *conn,
				const struct cred *conn_creds,
				const char *name);
bool kdbus_conn_policy_talk(struct kdbus_conn *conn,
			    const struct cred *conn_creds,
			    struct kdbus_conn *to);
bool kdbus_conn_policy_see_name_unlocked(struct kdbus_conn *conn,
					 const struct cred *curr_creds,
					 const char *name);
bool kdbus_conn_policy_see_notification(struct kdbus_conn *conn,
					const struct cred *curr_creds,
					const struct kdbus_kmsg *kmsg);

/* command dispatcher */
struct kdbus_conn *kdbus_cmd_hello(struct kdbus_ep *ep, bool privileged,
				   void __user *argp);
int kdbus_cmd_byebye_unlocked(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_conn_info(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_update(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_send(struct kdbus_conn *conn, struct file *f, void __user *argp);
int kdbus_cmd_recv(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_free(struct kdbus_conn *conn, void __user *argp);

/**
 * kdbus_conn_is_ordinary() - Check if connection is ordinary
 * @conn:		The connection to check
 *
 * Return: Non-zero if the connection is an ordinary connection
 */
static inline int kdbus_conn_is_ordinary(const struct kdbus_conn *conn)
{
	return !(conn->flags & KDBUS_HELLO_SPECIAL_CONN);
}

/**
 * kdbus_conn_is_activator() - Check if connection is an activator
 * @conn:		The connection to check
 *
 * Return: Non-zero if the connection is an activator
 */
static inline int kdbus_conn_is_activator(const struct kdbus_conn *conn)
{
	return conn->flags & KDBUS_HELLO_ACTIVATOR;
}

/**
 * kdbus_conn_is_policy_holder() - Check if connection is a policy holder
 * @conn:		The connection to check
 *
 * Return: Non-zero if the connection is a policy holder
 */
static inline int kdbus_conn_is_policy_holder(const struct kdbus_conn *conn)
{
	return conn->flags & KDBUS_HELLO_POLICY_HOLDER;
}

/**
 * kdbus_conn_is_monitor() - Check if connection is a monitor
 * @conn:		The connection to check
 *
 * Return: Non-zero if the connection is a monitor
 */
static inline int kdbus_conn_is_monitor(const struct kdbus_conn *conn)
{
	return conn->flags & KDBUS_HELLO_MONITOR;
}

/**
 * kdbus_conn_lock2() - Lock two connections
 * @a:		connection A to lock or NULL
 * @b:		connection B to lock or NULL
 *
 * Lock two connections at once. As we need to have a stable locking order, we
 * always lock the connection with lower memory address first.
 */
static inline void kdbus_conn_lock2(struct kdbus_conn *a, struct kdbus_conn *b)
{
	if (a < b) {
		if (a)
			mutex_lock(&a->lock);
		if (b && b != a)
			mutex_lock_nested(&b->lock, !!a);
	} else {
		if (b)
			mutex_lock(&b->lock);
		if (a && a != b)
			mutex_lock_nested(&a->lock, !!b);
	}
}

/**
 * kdbus_conn_unlock2() - Unlock two connections
 * @a:		connection A to unlock or NULL
 * @b:		connection B to unlock or NULL
 *
 * Unlock two connections at once. See kdbus_conn_lock2().
 */
static inline void kdbus_conn_unlock2(struct kdbus_conn *a,
				      struct kdbus_conn *b)
{
	if (a)
		mutex_unlock(&a->lock);
	if (b && b != a)
		mutex_unlock(&b->lock);
}

/**
 * kdbus_conn_assert_active() - lockdep assert on active lock
 * @conn:	connection that shall be active
 *
 * This verifies via lockdep that the caller holds an active reference to the
 * given connection.
 */
static inline void kdbus_conn_assert_active(struct kdbus_conn *conn)
{
	lockdep_assert_held(conn);
}

#endif
