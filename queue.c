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
#include <linux/device.h>
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

#include "connection.h"
#include "item.h"
#include "message.h"
#include "metadata.h"
#include "util.h"
#include "queue.h"

static int kdbus_queue_entry_fds_install(struct kdbus_queue_entry *entry,
					 int **ret_fds)
{
	unsigned int i;
	int ret, *fds;
	size_t size;

	/* get array of file descriptors */
	size = entry->fds_count * sizeof(int);
	fds = kmalloc(size, GFP_KERNEL);
	if (!fds)
		return -ENOMEM;

	/* allocate new file descriptors in the receiver's process */
	for (i = 0; i < entry->fds_count; i++) {
		fds[i] = get_unused_fd_flags(O_CLOEXEC);
		if (fds[i] < 0) {
			ret = fds[i];
			goto remove_unused;
		}
	}

	/* copy the array into the message item */
	ret = kdbus_pool_slice_copy(entry->slice, entry->fds, fds, size);
	if (ret < 0)
		goto remove_unused;

	/* install files in the receiver's process */
	for (i = 0; i < entry->fds_count; i++)
		fd_install(fds[i], get_file(entry->fds_fp[i]));

	kfree(fds);
	return 0;

remove_unused:
	for (i = 0; i < entry->fds_count; i++) {
		if (fds[i] < 0)
			break;

		put_unused_fd(fds[i]);
	}

	*ret_fds = fds;
	return ret;
}

static int kdbus_queue_entry_memfds_install(struct kdbus_queue_entry *entry,
					    int **memfds)
{
	int *fds;
	unsigned int i;
	size_t size;
	int ret = 0;

	size = entry->memfds_count * sizeof(int);
	fds = kmalloc(size, GFP_KERNEL);
	if (!fds)
		return -ENOMEM;

	/* allocate new file descriptors in the receiver's process */
	for (i = 0; i < entry->memfds_count; i++) {
		fds[i] = get_unused_fd_flags(O_CLOEXEC);
		if (fds[i] < 0) {
			ret = fds[i];
			goto remove_unused;
		}
	}

	/*
	 * Update the file descriptor number in the items. We remembered
	 * the locations of the values in the buffer.
	 */
	for (i = 0; i < entry->memfds_count; i++) {
		ret = kdbus_pool_slice_copy(entry->slice, entry->memfds[i],
					     &fds[i], sizeof(int));
		if (ret < 0)
			goto remove_unused;
	}

	/* install files in the receiver's process */
	for (i = 0; i < entry->memfds_count; i++)
		fd_install(fds[i], get_file(entry->memfds_fp[i]));

	*memfds = fds;
	return 0;

remove_unused:
	for (i = 0; i < entry->memfds_count; i++) {
		if (fds[i] < 0)
			break;

		put_unused_fd(fds[i]);
	}

	kfree(fds);
	*memfds = NULL;
	return ret;
}

/**
 * kdbus_queue_entry_install() - install message components into the
 *				 receiver's process
 * @entry:	The queue entry to install
 *
 * This function will install file descriptors into 'current'.
 * Also, it the associated message has metadata attached which's final values
 * couldn't be determined before (such as details that are related to name
 * spaces etc), the correct information is patched in at this point.
 *
 * Return: 0 on success.
 */
int kdbus_queue_entry_install(struct kdbus_queue_entry *entry)
{
	int *memfds = NULL;
	int *fds = NULL;
	unsigned int i;
	int ret = 0;

	/*
	 * Install KDBUS_MSG_PAYLOAD_MEMFDs file descriptors, we return
	 * the list of file descriptors to be able to cleanup on error.
	 */
	if (entry->memfds_count > 0) {
		ret = kdbus_queue_entry_memfds_install(entry, &memfds);
		if (ret < 0)
			return ret;
	}

	/* install KDBUS_MSG_FDS file descriptors */
	if (entry->fds_count > 0) {
		ret = kdbus_queue_entry_fds_install(entry, &fds);
		if (ret < 0)
			goto exit_rewind_memfds;
	}

	kfree(fds);
	kfree(memfds);
	kdbus_pool_slice_flush(entry->slice);

	return 0;

exit_rewind_memfds:
	for (i = 0; i < entry->memfds_count; i++)
		sys_close(memfds[i]);
	kfree(memfds);

	return ret;
}

static int kdbus_queue_entry_payload_add(struct kdbus_queue_entry *entry,
					 const struct kdbus_kmsg *kmsg,
					 size_t items, size_t vec_data)
{
	const struct kdbus_item *item;
	int ret;

	if (kmsg->memfds_count > 0) {
		entry->memfds = kcalloc(kmsg->memfds_count,
					sizeof(off_t), GFP_KERNEL);
		if (!entry->memfds)
			return -ENOMEM;

		entry->memfds_fp = kcalloc(kmsg->memfds_count,
					   sizeof(struct file *), GFP_KERNEL);
		if (!entry->memfds_fp)
			return -ENOMEM;
	}

	KDBUS_ITEMS_FOREACH(item, kmsg->msg.items,
			    KDBUS_ITEMS_SIZE(&kmsg->msg, items)) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			char tmp[KDBUS_ITEM_HEADER_SIZE +
				 sizeof(struct kdbus_vec)];
			struct kdbus_item *it = (struct kdbus_item *)tmp;

			/* add item */
			it->type = KDBUS_ITEM_PAYLOAD_OFF;
			it->size = sizeof(tmp);

			/* a NULL address specifies a \0-bytes record */
			if (KDBUS_PTR(item->vec.address))
				it->vec.offset = vec_data;
			else
				it->vec.offset = ~0ULL;
			it->vec.size = item->vec.size;
			ret = kdbus_pool_slice_copy(entry->slice, items,
						    it, it->size);
			if (ret < 0)
				return ret;
			items += KDBUS_ALIGN8(it->size);

			/* \0-bytes record */
			if (!KDBUS_PTR(item->vec.address)) {
				size_t l = item->vec.size % 8;
				const char *n = "\0\0\0\0\0\0\0";

				if (l == 0)
					break;

				/*
				 * Preserve the alignment for the next payload
				 * record in the output buffer; write as many
				 * null-bytes to the buffer which the \0-bytes
				 * record would have shifted the alignment.
				 */
				ret = kdbus_pool_slice_copy(entry->slice,
							    vec_data, n, l);
				if (ret < 0)
					return ret;

				vec_data += l;
				break;
			}

			/* copy kdbus_vec data from sender to receiver */
			ret = kdbus_pool_slice_copy_user(entry->slice, vec_data,
				KDBUS_PTR(item->vec.address), item->vec.size);
			if (ret < 0)
				return ret;

			vec_data += item->vec.size;
			break;
		}

		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			char tmp[KDBUS_ITEM_HEADER_SIZE +
				 sizeof(struct kdbus_memfd)];
			struct kdbus_item *it = (struct kdbus_item *)tmp;

			/* add item */
			it->type = KDBUS_ITEM_PAYLOAD_MEMFD;
			it->size = sizeof(tmp);
			it->memfd.size = item->memfd.size;
			it->memfd.fd = -1;
			ret = kdbus_pool_slice_copy(entry->slice, items,
						    it, it->size);
			if (ret < 0)
				return ret;

			/*
			 * Remember the file and the location of the fd number
			 * which will be updated at RECV time.
			 */
			entry->memfds[entry->memfds_count] =
				items + offsetof(struct kdbus_item, memfd.fd);
			entry->memfds_fp[entry->memfds_count] =
				get_file(kmsg->memfds[entry->memfds_count]);
			entry->memfds_count++;

			items += KDBUS_ALIGN8(it->size);
			break;
		}

		default:
			break;
		}
	}

	return 0;
}

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
		if (likely(entry->priority == e->priority)) {
			list_add_tail(&entry->prio_entry, &e->prio_entry);
			goto prio_done;
		}

		if (entry->priority < e->priority) {
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
 * @entry:		Pointer to return the peeked entry
 *
 * Look for a entry in a queue, either by priority, or the oldest one (FIFO).
 * The entry is not freed, put off the queue's lists or anything else.
 *
 * Return: 0 on success, -ENOMSG if there is no entry with the requested
 * priority, or -EAGAIN if there are no entries at all.
 */
int kdbus_queue_entry_peek(struct kdbus_queue *queue,
			   s64 priority, bool use_priority,
			   struct kdbus_queue_entry **entry)
{
	struct kdbus_queue_entry *e;

	if (queue->msg_count == 0)
		return -EAGAIN;

	if (use_priority) {
		/* get next entry with highest priority */
		e = rb_entry(queue->msg_prio_highest,
			     struct kdbus_queue_entry, prio_node);

		/* no entry with the requested priority */
		if (e->priority > priority)
			return -ENOMSG;
	} else {
		/* ignore the priority, return the next entry in the entry */
		e = list_first_entry(&queue->msg_list,
				     struct kdbus_queue_entry, entry);
	}

	*entry = e;

	return 0;
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
	if (entry->user >= 0) {
		BUG_ON(conn->msg_users[entry->user] == 0);
		conn->msg_users[entry->user]--;
		entry->user = -1;
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
 * @conn:	The connection that holds the queue
 * @kmsg:	The kmsg object the queue entry should track
 * @e:		Pointer to return the allocated entry
 *
 * Allocates a queue entry based on a given kmsg and allocate space for
 * the message payload and the requested metadata in the connection's pool.
 * The entry is not actually added to the queue's lists at this point.
 */
int kdbus_queue_entry_alloc(struct kdbus_conn *conn,
			    const struct kdbus_kmsg *kmsg,
			    struct kdbus_queue_entry **e)
{
	struct kdbus_queue_entry *entry;
	struct kdbus_item *it;
	u64 msg_size;
	size_t size;
	size_t dst_name_len = 0;
	size_t payloads = 0;
	size_t fds = 0;
	size_t meta_off = 0;
	size_t vec_data;
	size_t want, have;
	int ret = 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->user = -1;

	/* copy message properties we need for the entry management */
	entry->src_id = kmsg->msg.src_id;
	entry->cookie = kmsg->msg.cookie;

	/* space for the header */
	if (kmsg->msg.src_id == KDBUS_SRC_ID_KERNEL)
		size = kmsg->msg.size;
	else
		size = offsetof(struct kdbus_msg, items);
	msg_size = size;

	/* let the receiver know where the message was addressed to */
	if (kmsg->dst_name) {
		dst_name_len = strlen(kmsg->dst_name) + 1;
		msg_size += KDBUS_ITEM_SIZE(dst_name_len);
		entry->dst_name_id = kmsg->dst_name_id;
	}

	/* space for PAYLOAD items */
	if ((kmsg->vecs_count + kmsg->memfds_count) > 0) {
		payloads = msg_size;
		msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec)) *
			    kmsg->vecs_count;
		msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd)) *
			    kmsg->memfds_count;
	}

	/* space for FDS item */
	if (kmsg->fds_count > 0) {
		entry->fds_fp = kcalloc(kmsg->fds_count, sizeof(struct file *),
					GFP_KERNEL);
		if (!entry->fds_fp)
			return -ENOMEM;

		fds = msg_size;
		msg_size += KDBUS_ITEM_SIZE(kmsg->fds_count * sizeof(int));
	}

	/* space for metadata/credential items */
	if (kmsg->meta && kmsg->meta->size > 0 &&
	    kdbus_meta_ns_eq(kmsg->meta, conn->meta)) {
		meta_off = msg_size;
		msg_size += kmsg->meta->size;
	}

	/* data starts after the message */
	vec_data = KDBUS_ALIGN8(msg_size);

	/* do not give out more than half of the remaining space */
	want = vec_data + kmsg->vecs_size;
	have = kdbus_pool_remain(conn->pool);
	if (want < have && want > have / 2) {
		ret = -EXFULL;
		goto exit;
	}

	/* allocate the needed space in the pool of the receiver */
	ret = kdbus_pool_slice_alloc(conn->pool, &entry->slice, want);
	if (ret < 0)
		goto exit;

	/* copy the message header */
	ret = kdbus_pool_slice_copy(entry->slice, 0, &kmsg->msg, size);
	if (ret < 0)
		goto exit_pool_free;

	/* update the size */
	ret = kdbus_pool_slice_copy(entry->slice, 0, &msg_size,
				    sizeof(kmsg->msg.size));
	if (ret < 0)
		goto exit_pool_free;

	if (dst_name_len  > 0) {
		char tmp[KDBUS_ITEM_HEADER_SIZE + dst_name_len];

		it = (struct kdbus_item *)tmp;
		it->size = KDBUS_ITEM_HEADER_SIZE + dst_name_len;
		it->type = KDBUS_ITEM_DST_NAME;
		memcpy(it->str, kmsg->dst_name, dst_name_len);

		ret = kdbus_pool_slice_copy(entry->slice, size, it, it->size);
		if (ret < 0)
			goto exit_pool_free;
	}

	/* add PAYLOAD items */
	if (payloads > 0) {
		ret = kdbus_queue_entry_payload_add(entry, kmsg,
						    payloads, vec_data);
		if (ret < 0)
			goto exit_pool_free;
	}

	/* add a FDS item; the array content will be updated at RECV time */
	if (kmsg->fds_count > 0) {
		char tmp[KDBUS_ITEM_HEADER_SIZE];
		unsigned int i;

		it = (struct kdbus_item *)tmp;
		it->type = KDBUS_ITEM_FDS;
		it->size = KDBUS_ITEM_HEADER_SIZE +
			   (kmsg->fds_count * sizeof(int));
		ret = kdbus_pool_slice_copy(entry->slice, fds,
					    it, KDBUS_ITEM_HEADER_SIZE);
		if (ret < 0)
			goto exit_pool_free;

		for (i = 0; i < kmsg->fds_count; i++) {
			entry->fds_fp[i] = get_file(kmsg->fds[i]);
			if (!entry->fds_fp[i]) {
				ret = -EBADF;
				goto exit_pool_free;
			}
		}

		/* remember the array to update at RECV */
		entry->fds = fds + offsetof(struct kdbus_item, fds);
		entry->fds_count = kmsg->fds_count;
	}

	/* append message metadata/credential items */
	if (meta_off > 0) {
		ret = kdbus_pool_slice_copy(entry->slice, meta_off,
					    kmsg->meta->data,
					    kmsg->meta->size);
		if (ret < 0)
			goto exit_pool_free;
	}

	entry->priority = kmsg->msg.priority;
	*e = entry;
	return 0;

exit_pool_free:
	kdbus_pool_slice_free(entry->slice);
exit:
	kdbus_queue_entry_free(entry);
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
	kdbus_fput_files(entry->memfds_fp, entry->memfds_count);
	kdbus_fput_files(entry->fds_fp, entry->fds_count);
	kfree(entry->memfds_fp);
	kfree(entry->fds_fp);
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
