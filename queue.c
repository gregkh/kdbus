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
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_queue_entry *entry;
	const struct kdbus_item *item;
	int i, ret = 0;
	size_t pos;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	if (kmsg->dst_name) {
		entry->dst_name = kstrdup(kmsg->dst_name, GFP_KERNEL);
		if (!entry->dst_name) {
			ret = -ENOMEM;
			goto exit_free_entry;
		}
	}

	if (kmsg->vecs_count) {
		entry->vecs = kcalloc(kmsg->vecs_count,
				      sizeof(struct kdbus_queue_vec),
				      GFP_KERNEL);
		if (!entry->vecs) {
			ret = -ENOMEM;
			goto exit_free_entry;
		}
	}

	if (kmsg->fds_count) {
		entry->fds_fp = kcalloc(kmsg->fds_count,
					sizeof(struct file *), GFP_KERNEL);
		if (!entry->fds_fp) {
			ret = -ENOMEM;
			goto exit_free_entry;
		}

		for (i = 0; i < kmsg->fds_count; i++)
			entry->fds_fp[i] = get_file(kmsg->fds[i]);

		entry->fds_count = kmsg->fds_count;
	}

	if (kmsg->memfds_count) {
		entry->memfds_fp = kcalloc(kmsg->memfds_count,
					   sizeof(struct file *), GFP_KERNEL);
		if (!entry->memfds_fp) {
			ret = -ENOMEM;
			goto exit_free_entry;
		}

		entry->memfd_size = kcalloc(kmsg->memfds_count,
					    sizeof(size_t), GFP_KERNEL);
		if (!entry->memfd_size) {
			ret = -ENOMEM;
			goto exit_free_entry;
		}

		for (i = 0; i < kmsg->memfds_count; i++)
			entry->memfds_fp[i] = get_file(kmsg->memfds[i]);
	}

	INIT_LIST_HEAD(&entry->entry);
	entry->meta = kdbus_meta_ref(kmsg->meta);
	memcpy(&entry->msg, msg, sizeof(*msg));

	if (msg->src_id == KDBUS_SRC_ID_KERNEL) {
		size_t extra_size = msg->size - sizeof(*msg);

		entry->msg_extra = kmemdup((u8 *) msg + sizeof(*msg),
					   extra_size, GFP_KERNEL);
		if (!entry->msg_extra) {
			ret = -ENOMEM;
			goto exit_free_entry;
		}

		entry->msg_extra_size = extra_size;
	}

	if (kmsg->vecs_size > 0) {
		size_t want, have;

		/* do not give out more than half of the remaining space */
		want = kmsg->vecs_size;
		have = kdbus_pool_remain(pool);
		if (want < have && want > have / 2) {
			ret = -EXFULL;
			goto exit_free_entry;
		}

		/* allocate the needed space in the pool of the receiver */
		slice = kdbus_pool_slice_alloc(pool, want);
		if (IS_ERR(slice)) {
			ret = PTR_ERR(slice);
			goto exit_free_entry;
		}
	}

	pos = 0;

	KDBUS_ITEMS_FOREACH(item, msg->items, KDBUS_ITEMS_SIZE(msg, items))
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			void *addr = KDBUS_PTR(item->vec.address);
			const char *zeros = "\0\0\0\0\0\0\0";
			const void *copy_src;
			size_t copy_len;

			entry->vecs[entry->vec_count].size = item->vec.size;

			/* a NULL address specifies a \0-bytes record */
			if (addr) {
				entry->vecs[entry->vec_count].off = pos;
				copy_src = addr;
				copy_len = item->vec.size;
			} else {
				/*
				 *  \0-bytes record.
				 *
				 * Preserve the alignment for the next payload
				 * record in the output buffer; write as many
				 * null-bytes to the buffer which the \0-bytes
				 * record would have shifted the alignment.
				 */
				entry->vecs[entry->vec_count].off = ~0ULL;
				copy_src = zeros;
				copy_len = item->vec.size % 8;
			}


			ret = kdbus_pool_slice_copy(slice, pos,
						    copy_src, copy_len);
			if (ret < 0)
				goto exit_free_slice;

			pos += copy_len;
			entry->vec_count++;
			break;
		}

		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			entry->memfd_size[entry->memfds_count] =
						item->memfd.size;
			entry->memfds_count++;
			break;
		}

		default:
			break;
	}

	BUG_ON(entry->vec_count != kmsg->vecs_count);
	BUG_ON(entry->memfds_count != kmsg->memfds_count);

	entry->slice_vecs = slice;

	return entry;

exit_free_slice:
	kdbus_pool_slice_release(slice);
exit_free_entry:
	kdbus_queue_entry_free(entry);
	return ERR_PTR(ret);
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
	u8 *meta_buf = NULL, *items_buf;
	struct kdbus_item *item;
	off_t payload_off = 0;
	size_t pos;
	int i, ret;

	if (entry->meta) {
		ret = kdbus_meta_export(entry->meta, _KDBUS_ATTACH_ALL,
					&meta_buf, &meta_size);
		if (ret < 0)
			return ret;
	}

	/* sum up how much space we need for the 'control' part */
	items_size += entry->vec_count *
		      KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	items_size += entry->memfds_count *
		      KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));

	if (entry->fds_count)
		items_size += KDBUS_ITEM_SIZE(sizeof(int) * entry->fds_count);

	if (entry->dst_name)
		items_size += KDBUS_ITEM_SIZE(strlen(entry->dst_name) + 1);

	items_buf = kzalloc(items_size, GFP_KERNEL);
	if (!items_buf) {
		ret = -ENOMEM;
		goto exit_free_meta;
	}

	/*
	 * The offsets stored in the slice are relative to the the start
	 * of the payload slice. When exporting them, they need to become
	 * relative to the entire pool, so get the payload slice's offset
	 * first.
	 */
	if (entry->slice_vecs)
		payload_off = kdbus_pool_slice_offset(entry->slice_vecs);

	/* Now fill in the payload and file descriptor items */
	item = (struct kdbus_item *) items_buf;

	if (entry->dst_name) {
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     strlen(entry->dst_name) + 1;
		item->type = KDBUS_ITEM_DST_NAME;
		strcpy(item->str, entry->dst_name);
		item = KDBUS_ITEM_NEXT(item);
	}

	for (i = 0; i < entry->vec_count; i++) {
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     sizeof(struct kdbus_vec);
		item->type = KDBUS_ITEM_PAYLOAD_OFF;
		item->vec.offset = entry->vecs[i].off;
		if (entry->vecs[i].off != ~0ULL)
			item->vec.offset += payload_off;
		item->vec.size = entry->vecs[i].size;
		item = KDBUS_ITEM_NEXT(item);
	}

	for (i = 0; i < entry->memfds_count; i++) {
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     sizeof(struct kdbus_memfd);
		item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
		item->memfd.size = entry->memfd_size[i];

		if (install_fds) {
			item->memfd.fd = get_unused_fd_flags(O_CLOEXEC);
			if (item->memfd.fd >= 0)
				fd_install(item->memfd.fd,
					   get_file(entry->memfds_fp[i]));
		} else {
			item->memfd.fd = -1;
		}

		item = KDBUS_ITEM_NEXT(item);
	}

	if (entry->fds_count) {
		item->size = KDBUS_ITEM_HEADER_SIZE +
			     (sizeof(int) * entry->fds_count);
		item->type = KDBUS_ITEM_FDS;

		for (i = 0; i < entry->fds_count; i++) {
			if (install_fds) {
				item->fds[i] = get_unused_fd_flags(O_CLOEXEC);
				if (item->fds[i] >= 0)
					fd_install(item->fds[i],
						   get_file(entry->fds_fp[i]));
			} else {
				item->fds[i] = -1;
			}
		}

		item = KDBUS_ITEM_NEXT(item);
	}

	/* Make sure the sizes actually match */
	BUG_ON((u8 *) item != items_buf + items_size);

	/* Now that we know it, update the message size */
	entry->msg.size = sizeof(entry->msg) + entry->msg_extra_size +
			  meta_size + items_size;

	/* Allocate the needed space in the pool of the receiver */
	entry->slice = kdbus_pool_slice_alloc(conn_dst->pool, entry->msg.size);
	if (IS_ERR(entry->slice)) {
		ret = PTR_ERR(entry->slice);
		entry->slice = NULL;
		goto exit_free_slice;
	}

	kdbus_pool_slice_set_child(entry->slice, entry->slice_vecs);

	pos = 0;
	ret = kdbus_pool_slice_copy(entry->slice, pos,
				    &entry->msg, sizeof(entry->msg));
	if (ret < 0)
		goto exit_free_slice;

	pos += sizeof(entry->msg);
	ret = kdbus_pool_slice_copy(entry->slice, pos,
				    entry->msg_extra, entry->msg_extra_size);
	if (ret < 0)
		goto exit_free_slice;

	pos += entry->msg_extra_size;
	ret = kdbus_pool_slice_copy(entry->slice, pos,
				    items_buf, items_size);
	if (ret < 0)
		goto exit_free_slice;

	pos += items_size;
	ret = kdbus_pool_slice_copy(entry->slice, pos,
				    meta_buf, meta_size);
	if (ret < 0)
		goto exit_free_slice;

	kfree(items_buf);
	kfree(meta_buf);

	return 0;

exit_free_slice:
	kdbus_pool_slice_release(entry->slice);

exit_free_meta:
	kfree(items_buf);
	kfree(meta_buf);

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
	kdbus_fput_files(entry->memfds_fp, entry->memfds_count);
	kdbus_fput_files(entry->fds_fp, entry->fds_count);
	kdbus_meta_unref(entry->meta);
	kfree(entry->memfd_size);
	kfree(entry->memfds_fp);
	kfree(entry->msg_extra);
	kfree(entry->dst_name);
	kfree(entry->fds_fp);
	kfree(entry->vecs);
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
