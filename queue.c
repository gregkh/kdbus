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
 * @pool:	The pool to allocate the slice in
 * @kmsg:	The kmsg object the queue entry should track
 *
 * Allocates a queue entry based on a given kmsg and allocate space for
 * the message payload and the requested metadata in the connection's pool.
 * The entry is not actually added to the queue's lists at this point.
 *
 * Return: the allocated entry on success, or an ERR_PTR on failures.
 */
struct kdbus_queue_entry *kdbus_queue_entry_alloc(struct kdbus_pool *pool,
						  const struct kdbus_kmsg *kmsg)
{
	struct kdbus_msg_resources *res = kmsg->res;
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_queue_entry *entry;
	int ret = 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->entry);
	entry->msg_res = kdbus_msg_resources_ref(res);
	entry->meta = kdbus_meta_ref(kmsg->meta);
	memcpy(&entry->msg, msg, sizeof(*msg));

	if (res && res->vec_count) {
		size_t pool_avail = kdbus_pool_remain(pool);

		/* do not give out more than half of the remaining space */
		if (res->pool_size < pool_avail &&
		    res->pool_size > pool_avail / 2) {
			ret = -EXFULL;
			goto exit_free_entry;
		}

		/* allocate the needed space in the pool of the receiver */
		entry->slice_vecs = kdbus_pool_slice_alloc(pool, res->pool_size,
							   NULL, res->iov,
							   res->vec_count);
		if (IS_ERR(entry->slice_vecs)) {
			ret = PTR_ERR(entry->slice_vecs);
			entry->slice_vecs = NULL;
			goto exit_free_entry;
		}
	}

	if (msg->src_id == KDBUS_SRC_ID_KERNEL) {
		size_t extra_size = msg->size - sizeof(*msg);

		entry->msg_extra = kmemdup((u8 *)msg + sizeof(*msg),
					   extra_size, GFP_KERNEL);
		if (!entry->msg_extra) {
			ret = -ENOMEM;
			goto exit_free_slice;
		}

		entry->msg_extra_size = extra_size;
	}

	return entry;

exit_free_slice:
	kdbus_pool_slice_release(entry->slice_vecs);
exit_free_entry:
	kdbus_queue_entry_free(entry);
	return ERR_PTR(ret);
}

static struct kdbus_item *
kdbus_msg_make_items(const struct kdbus_msg_resources *res, off_t payload_off,
		     bool install_fds, u64 *return_flags, size_t *out_size)
{
	struct kdbus_item *items, *item;
	bool incomplete_fds = false;
	size_t i, size = 0;

	/* sum up how much space we need for the 'control' part */
	size += res->vec_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
	size += res->memfd_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));

	if (res->fds_count)
		size += KDBUS_ITEM_SIZE(sizeof(int) * res->fds_count);

	if (res->dst_name)
		size += KDBUS_ITEM_SIZE(strlen(res->dst_name) + 1);

	items = kzalloc(size, GFP_KERNEL);
	if (!items)
		return ERR_PTR(-ENOMEM);

	item = items;

	if (res->dst_name) {
		kdbus_item_set(item, KDBUS_ITEM_DST_NAME,
			       res->dst_name, strlen(res->dst_name) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	for (i = 0; i < res->data_count; ++i) {
		struct kdbus_msg_data *d = res->data + i;
		struct kdbus_memfd m = {};
		struct kdbus_vec v = {};

		switch (d->type) {
		case KDBUS_MSG_DATA_VEC:
			v.size = d->size;
			v.offset = d->vec.off;
			if (v.offset != ~0ULL)
				v.offset += payload_off;

			kdbus_item_set(item, KDBUS_ITEM_PAYLOAD_OFF,
				       &v, sizeof(v));
			item = KDBUS_ITEM_NEXT(item);
			break;

		case KDBUS_MSG_DATA_MEMFD:
			m.start = d->memfd.start;
			m.size = d->size;
			m.fd = -1;
			if (install_fds) {
				m.fd = get_unused_fd_flags(O_CLOEXEC);
				if (m.fd >= 0)
					fd_install(m.fd,
						   get_file(d->memfd.file));
				else
					incomplete_fds = true;
			}

			kdbus_item_set(item, KDBUS_ITEM_PAYLOAD_MEMFD,
				       &m, sizeof(m));
			item = KDBUS_ITEM_NEXT(item);
			break;
		}
	}

	if (res->fds_count) {
		kdbus_item_set(item, KDBUS_ITEM_FDS,
			       NULL, (sizeof(int) * res->fds_count));
		for (i = 0; i < res->fds_count; i++) {
			if (install_fds) {
				item->fds[i] = get_unused_fd_flags(O_CLOEXEC);
				if (item->fds[i] >= 0)
					fd_install(item->fds[i],
						   get_file(res->fds[i]));
				else
					incomplete_fds = true;
			} else {
				item->fds[i] = -1;
			}
		}

		item = KDBUS_ITEM_NEXT(item);
	}

	/* Make sure the sizes actually match */
	BUG_ON((u8 *)item != (u8 *)items + size);

	if (incomplete_fds)
		*return_flags |= KDBUS_RECV_RETURN_INCOMPLETE_FDS;

	*out_size = size;
	return items;
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
	size_t meta_size = 0, items_size = 0;
	struct kdbus_item *meta_items = NULL;
	struct kdbus_item *items = NULL;
	off_t payload_off = 0;
	struct kvec kvec[4];
	size_t kvec_count = 0;
	int ret = 0;

	if (entry->meta) {
		u64 attach_flags = atomic64_read(&conn_dst->attach_flags_recv);

		meta_items = kdbus_meta_export(entry->meta, attach_flags,
					       &meta_size);
		if (IS_ERR(meta_items)) {
			ret = PTR_ERR(meta_items);
			meta_items = NULL;
			goto exit_free;
		}
	}

	/*
	 * The offsets stored in the slice are relative to the the start
	 * of the payload slice. When exporting them, they need to become
	 * relative to the pool, so get the payload slice's offset first.
	 */
	if (entry->slice_vecs)
		payload_off = kdbus_pool_slice_offset(entry->slice_vecs);

	if (entry->msg_res) {
		items = kdbus_msg_make_items(entry->msg_res, payload_off,
					     install_fds, return_flags,
					     &items_size);
		if (IS_ERR(items)) {
			ret = PTR_ERR(items);
			items = NULL;
			goto exit_free;
		}
	}

	entry->msg.size = 0;

	kdbus_kvec_set(&kvec[kvec_count++], &entry->msg, sizeof(entry->msg),
		       &entry->msg.size);

	if (entry->msg_extra_size)
		kdbus_kvec_set(&kvec[kvec_count++], entry->msg_extra,
			       entry->msg_extra_size, &entry->msg.size);

	if (items_size)
		kdbus_kvec_set(&kvec[kvec_count++], items, items_size,
			       &entry->msg.size);

	if (meta_size)
		kdbus_kvec_set(&kvec[kvec_count++], meta_items, meta_size,
			       &entry->msg.size);

	entry->slice = kdbus_pool_slice_alloc(conn_dst->pool, entry->msg.size,
					      kvec, NULL, kvec_count);
	if (IS_ERR(entry->slice)) {
		ret = PTR_ERR(entry->slice);
		entry->slice = NULL;
		goto exit_free;
	}

	kdbus_pool_slice_set_child(entry->slice, entry->slice_vecs);

exit_free:
	kfree(meta_items);
	kfree(items);

	return ret;
}

/**
 * kdbus_queue_entry_move() - move an entry from one queue to another
 * @conn_src:	Connection holding the queue to copy from
 * @conn_dst:	Connection holding the queue to copy to
 * @entry:	The queue entry to move
 *
 * Return: 0 on success, nagative error otherwise
 */
int kdbus_queue_entry_move(struct kdbus_conn *conn_src,
			   struct kdbus_conn *conn_dst,
			   struct kdbus_queue_entry *entry)
{
	int ret = 0;

	if (entry->slice_vecs)
		ret = kdbus_pool_slice_move(conn_src->pool, conn_dst->pool,
					    &entry->slice_vecs);

	if (ret < 0)
		kdbus_queue_entry_free(entry);
	else
		kdbus_queue_entry_add(&conn_dst->queue, entry);

	return 0;
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
	kdbus_meta_unref(entry->meta);
	kfree(entry->msg_extra);
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
