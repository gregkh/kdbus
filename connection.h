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

#ifndef __KDBUS_CONNECTION_H
#define __KDBUS_CONNECTION_H

#include "defaults.h"
#include "util.h"
#include "metadata.h"
#include "pool.h"

/**
 * struct kdbus_conn - connection to a bus
 * @kref:		Reference count
 * @id:			Connection ID
 * @flags:		KDBUS_HELLO_* flags
 * @attach_flags:	KDBUS_ATTACH_* flags
 * @disconnected:	Invalidated data
 * @name:		Human-readable connection name, used for debugging
 * @bus:		The bus this connection belongs to
 * @ep:			The endpoint this connection belongs to
 * @lock:		Connection data lock
 * @msg_list:		Queue of messages
 * @msg_prio_queue:	Tree of messages, sorted by priority
 * @msg_prio_highest:	Cached entry for highest priority (lowest value) node
 * @msg_users:		Array to account the number of queued messages per
 *			individual user
 * @msg_users_max:	Size of the users array
 * @hentry:		Entry in ID <-> connection map
 * @ep_entry:		The enpoint this connection belongs to
 * @monitor_entry:	The connection is a monitor
 * @names_list:		List of well-known names
 * @names_queue_list:	Well-known names this connection waits for
 * @activator_of:	Well-known name entry this connection acts as an
 *			activator for
 * @reply_list:		List of connections this connection expects
 *			a reply from.
 * @work:		Delayed work to handle timeouts
 * @match_db:		Subscription filter to broadcast messages
 * @meta:		Active connection creator's metadata/credentials,
 *			either from the handle of from HELLO
 * @owner_meta:		The connection's metadata/credentials supplied by
 *			HELLO
 * @pool:		The user's buffer to receive messages
 * @user:		Owner of the connection
 * @cred:		The credentials of the connection at creation time
 * @name_count:		Number of owned well-known names
 * @msg_count:		Number of queued messages
 * @reply_count:	Number of requests this connection has issued, and
 *			waits for replies from the peer
 * @wait:		Wake up this endpoint
 */
struct kdbus_conn {
	struct kref kref;
	u64 id;
	u64 flags;
	u64 attach_flags;
	bool disconnected;
	const char *name;
	struct kdbus_bus *bus;
	struct kdbus_ep *ep;
	struct mutex lock;
	struct list_head msg_list;
	struct rb_root msg_prio_queue;
	struct rb_node *msg_prio_highest;
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
	size_t name_count;
	size_t msg_count;
	atomic_t reply_count;
	wait_queue_head_t wait;
};

struct kdbus_kmsg;
struct kdbus_conn_queue;
struct kdbus_name_registry;

int kdbus_conn_new(struct kdbus_ep *ep,
		   struct kdbus_cmd_hello *hello,
		   struct kdbus_meta *meta,
		   struct kdbus_conn **conn);
struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn);
struct kdbus_conn *kdbus_conn_unref(struct kdbus_conn *conn);
int kdbus_conn_disconnect(struct kdbus_conn *conn, bool ensure_queue_empty);
bool kdbus_conn_active(const struct kdbus_conn *conn);

int kdbus_cmd_msg_recv(struct kdbus_conn *conn,
		       struct kdbus_cmd_recv *recv);
int kdbus_cmd_msg_cancel(struct kdbus_conn *conn,
			 u64 cookie);
int kdbus_cmd_conn_info(struct kdbus_conn *conn,
			struct kdbus_cmd_conn_info *cmd_info,
			size_t size);
int kdbus_cmd_conn_update(struct kdbus_conn *conn,
			  const struct kdbus_cmd_update *cmd_update);
int kdbus_conn_kmsg_send(struct kdbus_ep *ep,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg);
int kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			     struct kdbus_conn *conn_src,
			     u64 name_id);
bool kdbus_conn_has_name(struct kdbus_conn *conn, const char *name);
#endif
