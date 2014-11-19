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

#ifndef __KDBUS_QUEUE_H
#define __KDBUS_QUEUE_H

struct kdbus_domain_user;

/**
 * struct kdbus_queue - a connection's message queue
 * @msg_count		Number of messages in the queue
 * @msg_list:		List head for kdbus_queue_entry objects
 * @msg_prio_queue:	RB tree root for messages, sorted by priority
 * @msg_prio_highest:	Link to the RB node referencing the message with the
 *			highest priority in the tree.
 */
struct kdbus_queue {
	size_t msg_count;
	struct list_head msg_list;
	struct rb_root msg_prio_queue;
	struct rb_node *msg_prio_highest;
};

/**
 * struct kdbus_queue_entry - messages waiting to be read
 * @entry:		Entry in the connection's list
 * @prio_node:		Entry in the priority queue tree
 * @prio_entry:		Queue tree node entry in the list of one priority
 * @priority:		Queueing priority of the message
 * @slice:		Allocated slice in the receiver's pool
 * @memfds:		Arrays of offsets where to update the installed
 *			fd number
 * @memfds_fp:		Array memfd files queued up for this message
 * @memfds_count:	Number of memfds
 * @fds:		Offset to array where to update the installed fd number
 * @fds_fp:		Array of passed files queued up for this message
 * @fds_count:		Number of files
 * @src_id:		The ID of the sender
 * @cookie:		Message cookie, used for replies
 * @dst_name_id:	The sequence number of the name this message is
 *			addressed to, 0 for messages sent to an ID
 * @reply:		The reply block if a reply to this message is expected.
 * @user:		Index in per-user message counter, -1 for unused
 */
struct kdbus_queue_entry {
	struct list_head entry;
	struct rb_node prio_node;
	struct list_head prio_entry;
	s64 priority;
	struct kdbus_pool_slice *slice;
	size_t *memfds;
	struct file **memfds_fp;
	unsigned int memfds_count;
	size_t fds;
	struct file **fds_fp;
	unsigned int fds_count;
	u64 src_id;
	u64 cookie;
	u64 dst_name_id;
	struct kdbus_conn_reply *reply;
	struct kdbus_domain_user *user;
};

struct kdbus_kmsg;

void kdbus_queue_init(struct kdbus_queue *queue);

struct kdbus_queue_entry *
kdbus_queue_entry_alloc(struct kdbus_conn *conn_src,
			struct kdbus_conn *conn_dst,
			const struct kdbus_kmsg *kmsg);
void kdbus_queue_entry_free(struct kdbus_queue_entry *entry);

void kdbus_queue_entry_add(struct kdbus_queue *queue,
			   struct kdbus_queue_entry *entry);
void kdbus_queue_entry_remove(struct kdbus_conn *conn,
			      struct kdbus_queue_entry *entry);
struct kdbus_queue_entry *kdbus_queue_entry_peek(struct kdbus_queue *queue,
						 s64 priority,
						 bool use_priority);
int kdbus_queue_entry_install(struct kdbus_queue_entry *entry);

#endif /* __KDBUS_QUEUE_H */
