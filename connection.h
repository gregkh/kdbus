/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 * Copyright (C) 2014 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_CONNECTION_H
#define __KDBUS_CONNECTION_H

#include <linux/atomic.h>
#include <linux/lockdep.h>
#include "limits.h"
#include "metadata.h"
#include "pool.h"
#include "queue.h"
#include "util.h"

#define KDBUS_HELLO_SPECIAL_CONN	(KDBUS_HELLO_ACTIVATOR | \
					 KDBUS_HELLO_POLICY_HOLDER | \
					 KDBUS_HELLO_MONITOR)

/**
 * struct kdbus_conn - connection to a bus
 * @kref:		Reference count
 * @active:		Active references to the connection
 * @id:			Connection ID
 * @flags:		KDBUS_HELLO_* flags
 * @attach_flags:	KDBUS_ATTACH_* flags
 * @name:		Human-readable connection name, used for debugging
 * @bus:		The bus this connection belongs to
 * @ep:			The endpoint this connection belongs to
 * @lock:		Connection data lock
 * @msg_users:		Array to account the number of queued messages per
 *			individual user
 * @msg_users_max:	Size of the users array
 * @hentry:		Entry in ID <-> connection map
 * @ep_entry:		Entry in endpoint
 * @monitor_entry:	Entry in monitor, if the connection is a monitor
 * @names_list:		List of well-known names
 * @names_queue_list:	Well-known names this connection waits for
 * @reply_list:		List of connections this connection expects
 *			a reply from.
 * @work:		Delayed work to handle timeouts
 * @activator_of:	Well-known name entry this connection acts as an
 *			activator for
 * @match_db:		Subscription filter to broadcast messages
 * @meta:		Active connection creator's metadata/credentials,
 *			either from the handle or from HELLO
 * @owner_meta:		The connection's metadata/credentials supplied by
 *			HELLO
 * @pool:		The user's buffer to receive messages
 * @user:		Owner of the connection
 * @cred:		The credentials of the connection at creation time
 * @name_count:		Number of owned well-known names
 * @reply_count:	Number of requests this connection has issued, and
 *			waits for replies from the peer
 * @wait:		Wake up this endpoint
 * @queue:		The message queue associcated with this connection
 */
struct kdbus_conn {
	struct kref kref;
	atomic_t active;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
	u64 id;
	u64 flags;
	atomic64_t attach_flags;
	const char *name;
	struct kdbus_bus *bus;
	struct kdbus_ep *ep;
	struct mutex lock;
	unsigned int *msg_users;
	unsigned int msg_users_max;
	struct hlist_node hentry;
	struct list_head ep_entry;
	struct list_head monitor_entry;
	struct list_head names_list;
	struct list_head names_queue_list;
	struct list_head reply_list;
	struct delayed_work work;
	struct kdbus_name_entry *activator_of;
	struct kdbus_match_db *match_db;
	struct kdbus_meta *meta;
	struct kdbus_meta *owner_meta;
	struct kdbus_pool *pool;
	struct kdbus_domain_user *user;
	const struct cred *cred;
	atomic_t name_count;
	atomic_t reply_count;
	wait_queue_head_t wait;
	struct kdbus_queue queue;
};

struct kdbus_kmsg;
struct kdbus_name_registry;

struct kdbus_conn *kdbus_conn_new(struct kdbus_ep *ep,
				  struct kdbus_cmd_hello *hello,
				  struct kdbus_meta *meta);
struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn);
struct kdbus_conn *kdbus_conn_unref(struct kdbus_conn *conn);
int kdbus_conn_acquire(struct kdbus_conn *conn);
void kdbus_conn_release(struct kdbus_conn *conn);
int kdbus_conn_disconnect(struct kdbus_conn *conn, bool ensure_queue_empty);
bool kdbus_conn_active(const struct kdbus_conn *conn);
void kdbus_conn_purge_policy_cache(struct kdbus_conn *conn);

int kdbus_cmd_msg_recv(struct kdbus_conn *conn,
		       struct kdbus_cmd_recv *recv);
int kdbus_cmd_msg_cancel(struct kdbus_conn *conn,
			 u64 cookie);
int kdbus_cmd_info(struct kdbus_conn *conn,
			struct kdbus_cmd_info *cmd_info);
int kdbus_cmd_conn_update(struct kdbus_conn *conn,
			  const struct kdbus_cmd_update *cmd_update);
int kdbus_conn_kmsg_send(struct kdbus_ep *ep,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg);
int kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			     struct kdbus_conn *conn_src,
			     u64 name_id);
bool kdbus_conn_has_name(struct kdbus_conn *conn, const char *name);

/**
 * kdbus_conn_is_connected() - Check if connection is ordinary
 * @conn:		The connection to check
 *
 * Return: Non-zero if the connection is an ordinary connection
 */
static inline int kdbus_conn_is_connected(const struct kdbus_conn *conn)
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
#endif
