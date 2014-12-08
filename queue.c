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

static struct kdbus_pool_slice *
kdbus_kmsg_make_vec_slice(const struct kdbus_msg_resources *res,
			  struct kdbus_pool *pool)
{
	char *zeros = "\0\0\0\0\0\0\0";
	struct kdbus_pool_slice *slice;
	size_t want, have;
	int i, ret;
	struct iovec *iov;

	BUG_ON(!res->vec_src_valid);

	/* do not give out more than half of the remaining space */
	want = res->vecs_size;
	have = kdbus_pool_remain(pool);
	if (want < have && want > have / 2)
		return ERR_PTR(-EXFULL);

	/* allocate the needed space in the pool of the receiver */
	slice = kdbus_pool_slice_alloc(pool, want);
	if (IS_ERR(slice))
		return slice;

	/* FIXME: move this iov to message resources */
	iov = kcalloc(res->vecs_count, sizeof(*iov), GFP_KERNEL);
	if (!iov) {
		ret = -ENOMEM;
		goto exit_free_slice;
	}

	for (i = 0; i < res->vecs_count; i++) {
		struct kdbus_msg_vec *v = res->vecs + i;

		if (v->off != ~0ULL) {
			iov[i].iov_base = v->src_addr;
			iov[i].iov_len = v->size;
		} else {
			iov[i].iov_base = zeros;
			iov[i].iov_len = v->size % 8;
		}
	}

	ret = kdbus_pool_slice_copy_user(slice, 0, iov, res->vecs_count,
					 res->vecs_size);
	kfree(iov);
	if (ret < 0)
		goto exit_free_slice;

	return slice;

exit_free_slice:
	kdbus_pool_slice_release(slice);
	return ERR_PTR(ret);
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
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_queue_entry *entry;
	int ret = 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->entry);
	entry->msg_res = kdbus_msg_resources_ref(kmsg->res);
	entry->meta = kdbus_meta_ref(kmsg->meta);
	memcpy(&entry->msg, msg, sizeof(*msg));

	if (kmsg->res && kmsg->res->vecs_size) {
		struct kdbus_pool_slice *slice;

		slice = kdbus_kmsg_make_vec_slice(kmsg->res, pool);
		if (IS_ERR(slice)) {
			ret = PTR_ERR(slice);
			goto exit_free_entry;
		}

		entry->slice_vecs = slice;
	}

	if (msg->src_id == KDBUS_SRC_ID_KERNEL) {
		size_t extra_size = msg->size - sizeof(*msg);

		entry->msg_extra = kmemdup((u8 *) msg + sizeof(*msg),
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
kdbus_msg_make_items(const struct kdbus_msg_resources *res,
		     off_t payload_off, bool install_fds, size_t *out_size)
{
	struct kdbus_item *items, *item;
	size_t size = 0;
	int i;

	/* sum up how much space we need for the 'control' part */
	size += res->vecs_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
	size += res->memfds_count * KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));

	if (res->fds_count)
		size += KDBUS_ITEM_SIZE(sizeof(int) * res->fds_count);

	if (res->dst_name)
		size += KDBUS_ITEM_SIZE(strlen(res->dst_name) + 1);

	items = (struct kdbus_item *) kmalloc(size, GFP_KERNEL);
	if (!items)
		return ERR_PTR(-ENOMEM);

	item = items;

	if (res->dst_name) {
		kdbus_item_set(item, KDBUS_ITEM_DST_NAME,
			       res->dst_name, strlen(res->dst_name) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	for (i = 0; i < res->vecs_count; i++) {
		struct kdbus_vec v;

		v.offset = res->vecs[i].off;
		if (v.offset != ~0ULL)
			v.offset += payload_off;
		v.size = res->vecs[i].size;

		kdbus_item_set(item, KDBUS_ITEM_PAYLOAD_OFF, &v, sizeof(v));
		item = KDBUS_ITEM_NEXT(item);
	}

	for (i = 0; i < res->memfds_count; i++) {
		struct kdbus_memfd m = {
			.size = res->memfd_sizes[i],
		};

		kdbus_item_set(item, KDBUS_ITEM_PAYLOAD_MEMFD, &m, sizeof(m));
		if (install_fds) {
			item->memfd.fd = get_unused_fd_flags(O_CLOEXEC);
			if (item->memfd.fd >= 0)
				fd_install(item->memfd.fd,
					   get_file(res->memfds[i]));
		} else {
			item->memfd.fd = -1;
		}

		item = KDBUS_ITEM_NEXT(item);
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
			} else {
				item->fds[i] = -1;
			}
		}

		item = KDBUS_ITEM_NEXT(item);
	}

	/* Make sure the sizes actually match */
	BUG_ON((u8 *) item != (u8 *) items + size);

	*out_size = size;
	return items;
}
/**
 * kdbus_queue_entry_install() - install message components into the
 *				 receiver's process
 * @entry:		The queue entry to install
 * @conn_dst:		The receiver connection
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
			      bool install_fds)
{
	size_t meta_size = 0, items_size = 0;
	struct kdbus_item *meta_items = NULL;
	struct kdbus_item *items = NULL;
	off_t payload_off = 0;
	struct iovec iov[4];
	size_t iov_count = 0;
	int ret;

	if (entry->meta) {
		meta_items = kdbus_meta_export(entry->meta, _KDBUS_ATTACH_ALL,
					       &meta_size);
		if (IS_ERR(meta_items))
			return PTR_ERR(meta_items);
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
					     install_fds, &items_size);
		if (IS_ERR(items)) {
			ret = PTR_ERR(items);
			goto exit_free_meta;
		}
	}

	/* Now that we know it, update the message size */
	entry->msg.size = sizeof(entry->msg) + entry->msg_extra_size +
			  meta_size + items_size;

	/* Allocate the needed space in the pool of the receiver */
	entry->slice = kdbus_pool_slice_alloc(conn_dst->pool, entry->msg.size);
	if (IS_ERR(entry->slice)) {
		ret = PTR_ERR(entry->slice);
		entry->slice = NULL;
		goto exit_free_items;
	}

	kdbus_pool_slice_set_child(entry->slice, entry->slice_vecs);

	iov[iov_count].iov_base = &entry->msg;
	iov[iov_count].iov_len = sizeof(entry->msg);
	iov_count++;

	if (entry->msg_extra_size) {
		iov[iov_count].iov_base = entry->msg_extra;
		iov[iov_count].iov_len = entry->msg_extra_size;
		iov_count++;
	}

	if (items_size) {
		iov[iov_count].iov_base = items;
		iov[iov_count].iov_len = items_size;
		iov_count++;
	}

	if (meta_size) {
		iov[iov_count].iov_base = meta_items;
		iov[iov_count].iov_len = meta_size;
		iov_count++;
	}

	ret = kdbus_pool_slice_copy(entry->slice, 0, iov,
				    iov_count, entry->msg.size);
	if (ret < 0)
		goto exit_free_slice;

	kfree(meta_items);
	kfree(items);

	return 0;

exit_free_slice:
	kdbus_pool_slice_release(entry->slice);
exit_free_items:
	kfree(items);
exit_free_meta:
	kfree(meta_items);

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
