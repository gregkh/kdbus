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

#ifndef __KDBUS_QUEUE_H
#define __KDBUS_QUEUE_H

struct kdbus_user;

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
 * @msg:		Message header, either as received from userspace
 *			process, or as crafted by the kernel as notification
 * @msg_extra:		For notifications, contains more fixed parts of a
 *			message, which will be copied to the final message
 *			slice verbatim.
 * @slice:		Slice in the receiver's pool for the message
 * @slice_vecs:		Slice in the receiver's pool for message payload
 * @memfds:		Arrays of offsets where to update the installed
 *			fd number
 * @dst_name:		Destination well-known-name
 * @vecs:		Array of struct kdbus_queue_vecs
 * @vec_count:		Number of elements in @vecs
 * @memfds_fp:		Array memfd files queued up for this message
 * @memfd_size:		Array of size_t values, describing the sizes of memfds
 * @memfds_count:	Number of elements in @memfds_fp
 * @fds_fp:		Array of passed files queued up for this message
 * @fds_count:		Number of elements in @fds_fp
 * @dst_name_id:	The sequence number of the name this message is
 *			addressed to, 0 for messages sent to an ID
 * @proc_meta:		Process metadata, captured at message arrival
 * @conn_meta:		Connection metadata, captured at message arrival
 * @reply:		The reply block if a reply to this message is expected.
 * @user:		Index in per-user message counter, -1 for unused
 */
struct kdbus_queue_entry {
	struct list_head entry;
	struct rb_node prio_node;
	struct list_head prio_entry;

	struct kdbus_msg msg;

	struct kdbus_pool_slice *slice;

	u64 attach_flags;
	size_t meta_offset;
	size_t fds_offset;
	size_t *memfd_offset;

	u64 dst_name_id;

	struct kdbus_msg_resources *msg_res;
	struct kdbus_meta_proc *proc_meta;
	struct kdbus_meta_conn *conn_meta;
	struct kdbus_reply *reply;
	struct kdbus_user *user;
};

struct kdbus_kmsg;

void kdbus_queue_init(struct kdbus_queue *queue);

struct kdbus_queue_entry *
kdbus_queue_entry_alloc(struct kdbus_conn *conn_dst,
			const struct kdbus_kmsg *kmsg);
int kdbus_queue_entry_move(struct kdbus_conn *conn_dst,
			   struct kdbus_queue_entry *entry);
void kdbus_queue_entry_free(struct kdbus_queue_entry *entry);

void kdbus_queue_entry_add(struct kdbus_queue *queue,
			   struct kdbus_queue_entry *entry);
void kdbus_queue_entry_remove(struct kdbus_conn *conn,
			      struct kdbus_queue_entry *entry);
struct kdbus_queue_entry *kdbus_queue_entry_peek(struct kdbus_queue *queue,
						 s64 priority,
						 bool use_priority);
int kdbus_queue_entry_install(struct kdbus_queue_entry *entry,
			      struct kdbus_conn *conn_dst,
			      u64 *return_flags, bool install_fds);

#endif /* __KDBUS_QUEUE_H */
