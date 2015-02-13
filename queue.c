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
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include "util.h"
#include "domain.h"
#include "connection.h"
#include "item.h"
#include "message.h"
#include "metadata.h"
#include "queue.h"
#include "reply.h"

/**
 * kdbus_queue_entry_add() - Add an queue entry to a queue
 * @queue:	The queue to attach the item to
 * @entry:	The entry to attach
 *
 * Adds a previously allocated queue item to a queue, and maintains the
 * priority r/b tree.
 */
/* add queue entry to connection, maintain priority queue */
void kdbus_queue_entry_add(struct kdbus_queue *queue,
			   struct kdbus_queue_entry *entry)
{
	struct rb_node **n, *pn = NULL;
	bool highest = true;

	/* sort into priority entry tree */
	n = &queue->msg_prio_queue.rb_node;
	while (*n) {
		struct kdbus_queue_entry *e;

		pn = *n;
		e = rb_entry(pn, struct kdbus_queue_entry, prio_node);

		/* existing node for this priority, add to its list */
		if (likely(entry->msg.priority == e->msg.priority)) {
			list_add_tail(&entry->prio_entry, &e->prio_entry);
			goto prio_done;
		}

		if (entry->msg.priority < e->msg.priority) {
			n = &pn->rb_left;
		} else {
			n = &pn->rb_right;
			highest = false;
		}
	}

	/* cache highest-priority entry */
	if (highest)
		queue->msg_prio_highest = &entry->prio_node;

	/* new node for this priority */
	rb_link_node(&entry->prio_node, pn, n);
	rb_insert_color(&entry->prio_node, &queue->msg_prio_queue);
	INIT_LIST_HEAD(&entry->prio_entry);

prio_done:
	/* add to unsorted fifo list */
	list_add_tail(&entry->entry, &queue->msg_list);
	queue->msg_count++;
}

/**
 * kdbus_queue_entry_peek() - Retrieves an entry from a queue
 *
 * @queue:		The queue
 * @priority:		The minimum priority of the entry to peek
 * @use_priority:	Boolean flag whether or not to peek by priority
 *
 * Look for a entry in a queue, either by priority, or the oldest one (FIFO).
 * The entry is not freed, put off the queue's lists or anything else.
 *
 * Return: the peeked queue entry on success, ERR_PTR(-ENOMSG) if there is no
 * entry with the requested priority, or ERR_PTR(-EAGAIN) if there are no
 * entries at all.
 */
struct kdbus_queue_entry *kdbus_queue_entry_peek(struct kdbus_queue *queue,
						 s64 priority,
						 bool use_priority)
{
	struct kdbus_queue_entry *e;

	if (queue->msg_count == 0)
		return ERR_PTR(-EAGAIN);

	if (use_priority) {
		/* get next entry with highest priority */
		e = rb_entry(queue->msg_prio_highest,
			     struct kdbus_queue_entry, prio_node);

		/* no entry with the requested priority */
		if (e->msg.priority > priority)
			return ERR_PTR(-ENOMSG);
	} else {
		/* ignore the priority, return the next entry in the entry */
		e = list_first_entry(&queue->msg_list,
				     struct kdbus_queue_entry, entry);
	}

	return e;
}

/**
 * kdbus_queue_entry_remove() - Remove an entry from a queue
 * @conn:	The connection containing the queue
 * @entry:	The entry to remove
 *
 * Remove an entry from both the queue's list and the priority r/b tree.
 */
void kdbus_queue_entry_remove(struct kdbus_conn *conn,
			      struct kdbus_queue_entry *entry)
{
	struct kdbus_queue *queue = &conn->queue;

	list_del(&entry->entry);
	queue->msg_count--;

	/* user quota */
	if (entry->user) {
		BUG_ON(conn->msg_users[entry->user->idr] == 0);
		conn->msg_users[entry->user->idr]--;
		entry->user = kdbus_domain_user_unref(entry->user);
	}

	/* the queue is empty, remove the user quota accounting */
	if (queue->msg_count == 0 && conn->msg_users_max > 0) {
		kfree(conn->msg_users);
		conn->msg_users = NULL;
		conn->msg_users_max = 0;
	}

	if (list_empty(&entry->prio_entry)) {
		/*
		 * Single entry for this priority, update cached
		 * highest-priority entry, remove the tree node.
		 */
		if (queue->msg_prio_highest == &entry->prio_node)
			queue->msg_prio_highest = rb_next(&entry->prio_node);

		rb_erase(&entry->prio_node, &queue->msg_prio_queue);
	} else {
		struct kdbus_queue_entry *q;

		/*
		 * Multiple entries for this priority entry, get next one in
		 * the list. Update cached highest-priority entry, store the
		 * new one as the tree node.
		 */
		q = list_first_entry(&entry->prio_entry,
				     struct kdbus_queue_entry, prio_entry);
		list_del(&entry->prio_entry);

		if (queue->msg_prio_highest == &entry->prio_node)
			queue->msg_prio_highest = &q->prio_node;

		rb_replace_node(&entry->prio_node, &q->prio_node,
				&queue->msg_prio_queue);
	}
}

/**
 * kdbus_queue_entry_alloc() - allocate a queue entry
 * @conn_dst:	The destination connection
 * @kmsg:	The kmsg object the queue entry should track
 *
 * Allocates a queue entry based on a given kmsg and allocate space for
 * the message payload and the requested metadata in the connection's pool.
 * The entry is not actually added to the queue's lists at this point.
 *
 * Return: the allocated entry on success, or an ERR_PTR on failures.
 */
struct kdbus_queue_entry *kdbus_queue_entry_alloc(struct kdbus_conn *conn_dst,
						  const struct kdbus_kmsg *kmsg)
{
	struct kdbus_msg_resources *res = kmsg->res;
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_queue_entry *entry;
	struct kdbus_item_header hdr;
	size_t memfd_cnt = 0;
	struct kvec kvec[2];
	size_t pool_avail;
	size_t meta_size;
	size_t msg_size;
	u64 payload_off;
	u64 size = 0;
	int ret = 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->entry);
	entry->msg_res = kdbus_msg_resources_ref(res);
	entry->proc_meta = kdbus_meta_proc_ref(kmsg->proc_meta);
	entry->conn_meta = kdbus_meta_conn_ref(kmsg->conn_meta);
	memcpy(&entry->msg, msg, sizeof(*msg));

	if (kmsg->msg.src_id == KDBUS_SRC_ID_KERNEL)
		msg_size = msg->size;
	else
		msg_size = offsetof(struct kdbus_msg, items);

	/* sum up the size of the needed slice */
	size = msg_size;

	if (res) {
		size += res->vec_count *
			KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

		if (res->memfd_count) {
			entry->memfd_offset =
				kcalloc(sizeof(size_t), res->memfd_count,
					GFP_KERNEL);
			if (!entry->memfd_offset) {
				ret = -ENOMEM;
				goto exit_free_entry;
			}

			size += res->memfd_count *
				KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
		}

		if (res->fds_count)
			size += KDBUS_ITEM_SIZE(sizeof(int) * res->fds_count);

		if (res->dst_name)
			size += KDBUS_ITEM_SIZE(strlen(res->dst_name) + 1);
	}

	/*
	 * Remember the offset of the metadata part, so we can override
	 * this part later during kdbus_queue_entry_install().
	 */
	entry->meta_offset = size;

	if (entry->proc_meta || entry->conn_meta) {
		entry->attach_flags =
			atomic64_read(&conn_dst->attach_flags_recv);

		ret = kdbus_meta_export_prepare(entry->proc_meta,
						entry->conn_meta,
						&entry->attach_flags,
						&meta_size);
		if (ret < 0)
			goto exit_free_entry;

		size += meta_size;
	}

	payload_off = size;
	size += kmsg->pool_size;

	pool_avail = kdbus_pool_remain(conn_dst->pool);

	/* do not give out more than half of the remaining space */
	if (size > pool_avail / 2) {
		ret = -EXFULL;
		goto exit_free_entry;
	}

	entry->slice = kdbus_pool_slice_alloc(conn_dst->pool, size);
	if (IS_ERR(entry->slice)) {
		ret = PTR_ERR(entry->slice);
		entry->slice = NULL;
		goto exit_free_entry;
	}

	/* copy message header */
	kvec[0].iov_base = (char *) msg;
	kvec[0].iov_len = msg_size;

	ret = kdbus_pool_slice_copy_kvec(entry->slice, 0, kvec, 1, msg_size);
	if (ret < 0)
		goto exit_free_entry;

	/* 'size' will now track the write position */
	size = msg_size;

	/* create message payload items */
	if (res) {
		unsigned int i;

		if (res->dst_name) {
			size_t slen = strlen(res->dst_name) + 1;

			hdr.type = KDBUS_ITEM_DST_NAME;
			hdr.size = KDBUS_ITEM_HEADER_SIZE + slen;

			kvec[0].iov_base = &hdr;
			kvec[0].iov_len = sizeof(hdr);

			kvec[1].iov_base = (char *) res->dst_name;
			kvec[1].iov_len = slen;

			ret = kdbus_pool_slice_copy_kvec(entry->slice, size,
							 kvec, 2, hdr.size);
			if (ret < 0)
				goto exit_free_entry;

			size += KDBUS_ITEM_SIZE(slen);
		}

		for (i = 0; i < res->data_count; ++i) {
			struct kdbus_msg_data *d = res->data + i;
			struct kdbus_vec v = {};

			switch (d->type) {
			case KDBUS_MSG_DATA_VEC:
				v.size = d->size;
				v.offset = d->vec.off;
				if (v.offset != ~0ULL)
					v.offset += payload_off;

				hdr.type = KDBUS_ITEM_PAYLOAD_OFF;
				hdr.size = KDBUS_ITEM_HEADER_SIZE + sizeof(v);

				kvec[0].iov_base = &hdr;
				kvec[0].iov_len = sizeof(hdr);

				kvec[1].iov_base = &v;
				kvec[1].iov_len = sizeof(v);

				ret = kdbus_pool_slice_copy_kvec(entry->slice,
								 size, kvec, 2,
								 hdr.size);
				if (ret < 0)
					goto exit_free_entry;

				size += hdr.size;
				break;

			case KDBUS_MSG_DATA_MEMFD:
				/*
				 * Remember the location of memfds, so we can
				 * override the content from
				 * kdbus_queue_entry_install().
				 */
				entry->memfd_offset[memfd_cnt++] = size;
				size += KDBUS_ITEM_HEADER_SIZE +
					sizeof(struct kdbus_memfd);

				break;
			}
		}

		/*
		 * Remember the location of the FD part, so we can override the
		 * content in kdbus_queue_entry_install().
		 */
		if (res->fds_count) {
			entry->fds_offset = size;
			size += KDBUS_ITEM_SIZE(sizeof(int) * res->fds_count);
		}
	}

	/* finally, copy over the actual message payload */
	if (kmsg->iov_count) {
		ret = kdbus_pool_slice_copy_iovec(entry->slice, payload_off,
						  kmsg->iov,
						  kmsg->iov_count,
						  kmsg->pool_size);
		if (ret < 0)
			goto exit_free_entry;
	}

	return entry;

exit_free_entry:
	kdbus_queue_entry_free(entry);
	return ERR_PTR(ret);
}

/**
 * kdbus_queue_entry_install() - install message components into the
 *				 receiver's process
 * @entry:		The queue entry to install
 * @conn_dst:		The receiver connection
 * @return_flags:	Pointer to store the return flags for userspace
 * @install_fds:	Whether or not to install associated file descriptors
 *
 * This function will create a slice to transport the message header, the
 * metadata items and other items for information stored in @entry, and
 * store it as entry->slice.
 *
 * If @install_fds is %true, file descriptors will as well be installed.
 * This function must always be called from the task context of the receiver.
 *
 * Return: 0 on success.
 */
int kdbus_queue_entry_install(struct kdbus_queue_entry *entry,
			      struct kdbus_conn *conn_dst,
			      u64 *return_flags, bool install_fds)
{
	u64 msg_size = entry->meta_offset;
	struct kdbus_msg_resources *res;
	bool incomplete_fds = false;
	struct kvec kvec[2];
	size_t memfds = 0;
	int i, ret;

	if (entry->proc_meta || entry->conn_meta) {
		size_t meta_size;

		ret = kdbus_meta_export(entry->proc_meta,
					entry->conn_meta,
					entry->attach_flags,
					entry->slice,
					entry->meta_offset,
					&meta_size);
		if (ret < 0)
			return ret;

		msg_size += meta_size;
	}

	/* Update message size at offset 0 */
	kvec[0].iov_base = &msg_size;
	kvec[0].iov_len = sizeof(msg_size);

	ret = kdbus_pool_slice_copy_kvec(entry->slice, 0, kvec, 1,
					 sizeof(msg_size));
	if (ret < 0)
		return ret;

	res = entry->msg_res;

	if (!res)
		return 0;

	if (res->fds_count) {
		struct kdbus_item_header hdr;
		size_t off;
		int *fds;

		fds = kmalloc_array(res->fds_count, sizeof(int), GFP_KERNEL);
		if (!fds)
			return -ENOMEM;

		for (i = 0; i < res->fds_count; i++) {
			if (install_fds) {
				fds[i] = get_unused_fd_flags(O_CLOEXEC);
				if (fds[i] >= 0)
					fd_install(fds[i],
						   get_file(res->fds[i]));
				else
					incomplete_fds = true;
			} else {
				fds[i] = -1;
			}
		}

		off = entry->fds_offset;

		hdr.type = KDBUS_ITEM_FDS;
		hdr.size = KDBUS_ITEM_HEADER_SIZE +
			   sizeof(int) * res->fds_count;

		kvec[0].iov_base = &hdr;
		kvec[0].iov_len = sizeof(hdr);

		kvec[1].iov_base = fds;
		kvec[1].iov_len = sizeof(int) * res->fds_count;

		ret = kdbus_pool_slice_copy_kvec(entry->slice, off,
						 kvec, 2, hdr.size);
		kfree(fds);

		if (ret < 0)
			return ret;
	}

	for (i = 0; i < res->data_count; ++i) {
		struct kdbus_msg_data *d = res->data + i;
		struct kdbus_item_header hdr;
		struct kdbus_memfd m;

		if (d->type != KDBUS_MSG_DATA_MEMFD)
			continue;

		m.start = d->memfd.start;
		m.size = d->size;
		m.fd = -1;

		if (install_fds) {
			m.fd = get_unused_fd_flags(O_CLOEXEC);
			if (m.fd < 0) {
				m.fd = -1;
				incomplete_fds = true;
			} else {
				fd_install(m.fd,
					   get_file(d->memfd.file));
			}
		}

		hdr.type = KDBUS_ITEM_PAYLOAD_MEMFD;
		hdr.size = KDBUS_ITEM_HEADER_SIZE + sizeof(m);

		kvec[0].iov_base = &hdr;
		kvec[0].iov_len = sizeof(hdr);

		kvec[1].iov_base = &m;
		kvec[1].iov_len = sizeof(m);

		ret = kdbus_pool_slice_copy_kvec(entry->slice,
						 entry->memfd_offset[memfds++],
						 kvec, 2, hdr.size);
		if (ret < 0)
			return ret;
	}

	if (incomplete_fds)
		*return_flags |= KDBUS_RECV_RETURN_INCOMPLETE_FDS;

	return 0;
}

/**
 * kdbus_queue_entry_move() - move an entry from one queue to another
 * @conn_dst:	Connection holding the queue to copy to
 * @entry:	The queue entry to move
 *
 * Return: 0 on success, nagative error otherwise
 */
int kdbus_queue_entry_move(struct kdbus_conn *conn_dst,
			   struct kdbus_queue_entry *entry)
{
	int ret = 0;

	if (entry->slice)
		ret = kdbus_pool_slice_move(conn_dst->pool, &entry->slice);

	if (ret < 0)
		kdbus_queue_entry_free(entry);
	else
		kdbus_queue_entry_add(&conn_dst->queue, entry);

	return ret;
}

/**
 * kdbus_queue_entry_free() - free resources of an entry
 * @entry:	The entry to free
 *
 * Removes resources allocated by a queue entry, along with the entry itself.
 * Note that the entry's slice is not freed at this point.
 */
void kdbus_queue_entry_free(struct kdbus_queue_entry *entry)
{
	kdbus_msg_resources_unref(entry->msg_res);
	kdbus_meta_conn_unref(entry->conn_meta);
	kdbus_meta_proc_unref(entry->proc_meta);
	kdbus_reply_unref(entry->reply);
	kfree(entry->memfd_offset);
	kfree(entry);
}

/**
 * kdbus_queue_init() - initialize data structure related to a queue
 * @queue:	The queue to initialize
 */
void kdbus_queue_init(struct kdbus_queue *queue)
{
	INIT_LIST_HEAD(&queue->msg_list);
	queue->msg_prio_queue = RB_ROOT;
}
