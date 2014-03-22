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

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "match.h"
#include "memfd.h"
#include "message.h"
#include "metadata.h"
#include "names.h"
#include "domain.h"
#include "notify.h"
#include "policy.h"
#include "util.h"

struct kdbus_conn_reply;

/**
 * struct kdbus_conn_queue - messages waiting to be read
 * @entry:		Entry in the connection's list
 * @prio_node:		Entry in the priority queue tree
 * @prio_entry:		Queue tree node entry in the list of one priority
 * @priority:		Queueing priority of the message
 * @off:		Offset into the shmem file in the receiver's pool
 * @size:		The number of bytes used in the pool
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
struct kdbus_conn_queue {
	struct list_head entry;
	struct rb_node prio_node;
	struct list_head prio_entry;
	s64 priority;
	size_t off;
	size_t size;
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
	int user;
};

/**
 * struct kdbus_conn_reply - an entry of kdbus_conn's list of replies
 * @entry:		The entry of the connection's reply_list
 * @conn:		The counterpart connection that is expected to answer
 * @queue:		The queue item that is prepared by the replying
 *			connection
 * @deadline_ns:	The deadline of the reply, in nanoseconds
 * @cookie:		The cookie of the requesting message
 * @wait:		The waitqueue for synchronous I/O
 * @sync:		The reply block is waiting for synchronous I/O
 * @waiting:		The condition to synchronously wait for
 * @err:		The error code for the synchronous reply
 */
struct kdbus_conn_reply {
	struct list_head entry;
	struct kdbus_conn *conn;
	struct kdbus_conn_queue *queue;
	u64 deadline_ns;
	u64 cookie;
	wait_queue_head_t wait;
	bool sync:1;
	bool waiting:1;
	int err;
};

static void kdbus_conn_reply_free(struct kdbus_conn_reply *reply)
{
	atomic_dec(&reply->conn->reply_count);
	kdbus_conn_unref(reply->conn);
	kfree(reply);
}

static void kdbus_conn_reply_sync(struct kdbus_conn_reply *reply, int err)
{
	BUG_ON(!reply->sync);

	list_del(&reply->entry);
	reply->waiting = false;
	reply->err = err;
	wake_up_interruptible(&reply->wait);
}

static void kdbus_conn_fds_unref(struct kdbus_conn_queue *queue)
{
	unsigned int i;

	if (!queue->fds_fp)
		return;

	for (i = 0; i < queue->fds_count; i++) {
		if (!queue->fds_fp[i])
			break;

		fput(queue->fds_fp[i]);
	}

	kfree(queue->fds_fp);
	queue->fds_fp = NULL;

	queue->fds_count = 0;
}

/* grab references of passed-in FDS for the queued message */
static int kdbus_conn_fds_ref(struct kdbus_conn_queue *queue,
			      const int *fds, unsigned int fds_count)
{
	unsigned int i;

	queue->fds_fp = kcalloc(fds_count, sizeof(struct file *), GFP_KERNEL);
	if (!queue->fds_fp)
		return -ENOMEM;

	for (i = 0; i < fds_count; i++) {
		queue->fds_fp[i] = fget(fds[i]);
		if (!queue->fds_fp[i]) {
			kdbus_conn_fds_unref(queue);
			return -EBADF;
		}
	}

	return 0;
}

static void kdbus_conn_memfds_unref(struct kdbus_conn_queue *queue)
{
	unsigned int i;

	if (!queue->memfds_fp)
		return;

	for (i = 0; i < queue->memfds_count; i++) {
		if (!queue->memfds_fp[i])
			break;

		fput(queue->memfds_fp[i]);
	}

	kfree(queue->memfds_fp);
	queue->memfds_fp = NULL;

	kfree(queue->memfds);
	queue->memfds = NULL;

	queue->memfds_count = 0;
}

/* Validate the state of the incoming PAYLOAD_MEMFD, and grab a reference
 * to put it into the receiver's queue. */
static int kdbus_conn_memfd_ref(const struct kdbus_item *item,
				struct file **file)
{
	struct file *fp;
	int ret;

	fp = fget(item->memfd.fd);
	if (!fp)
		return -EBADF;

	/*
	 * We only accept kdbus_memfd files as payload, other files need to
	 * be passed with KDBUS_MSG_FDS.
	 */
	if (!kdbus_is_memfd(fp)) {
		ret = -EMEDIUMTYPE;
		goto exit_unref;
	}

	/* We only accept a sealed memfd file whose content cannot be altered
	 * by the sender or anybody else while it is shared or in-flight. */
	if (!kdbus_is_memfd_sealed(fp)) {
		ret = -ETXTBSY;
		goto exit_unref;
	}

	/* The specified size in the item cannot be larger than the file. */
	if (item->memfd.size > kdbus_memfd_size(fp)) {
		ret = -EBADF;
		goto exit_unref;
	}

	*file = fp;
	return 0;

exit_unref:
	fput(fp);
	return ret;
}

static int kdbus_conn_payload_add(struct kdbus_conn *conn,
				  struct kdbus_conn_queue *queue,
				  const struct kdbus_kmsg *kmsg,
				  size_t off, size_t items, size_t vec_data)
{
	const struct kdbus_item *item;
	int ret;

	if (kmsg->memfds_count > 0) {
		queue->memfds = kcalloc(kmsg->memfds_count,
					sizeof(size_t), GFP_KERNEL);
		if (!queue->memfds)
			return -ENOMEM;

		queue->memfds_fp = kcalloc(kmsg->memfds_count,
					   sizeof(struct file *), GFP_KERNEL);
		if (!queue->memfds_fp)
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
			ret = kdbus_pool_write(conn->pool, off + items,
					       it, it->size);
			if (ret < 0)
				return ret;
			items += KDBUS_ALIGN8(it->size);

			/* \0-bytes record */
			if (!KDBUS_PTR(item->vec.address)) {
				size_t pad = item->vec.size % 8;

				if (pad == 0)
					break;

				/*
				 * Preserve the alignment for the next payload
				 * record in the output buffer; write as many
				 * null-bytes to the buffer which the \0-bytes
				 * record would have shifted the alignment.
				 */
				kdbus_pool_write_user(conn->pool,
						      off + vec_data,
						      (char __user *)
							"\0\0\0\0\0\0\0", pad);
				vec_data += pad;
				break;
			}

			/* copy kdbus_vec data from sender to receiver */
			ret = kdbus_pool_write_user(conn->pool, off + vec_data,
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
			struct file *fp;
			size_t memfd;

			/* add item */
			it->type = KDBUS_ITEM_PAYLOAD_MEMFD;
			it->size = sizeof(tmp);
			it->memfd.size = item->memfd.size;
			it->memfd.fd = -1;
			ret = kdbus_pool_write(conn->pool, off + items,
					       it, it->size);
			if (ret < 0)
				return ret;

			/* grab reference of incoming file */
			ret = kdbus_conn_memfd_ref(item, &fp);
			if (ret < 0)
				return ret;

			/*
			 * Remember the file and the location of the fd number
			 * which will be updated at RECV time.
			 */
			memfd = items + offsetof(struct kdbus_item, memfd.fd);
			queue->memfds[queue->memfds_count] = memfd;
			queue->memfds_fp[queue->memfds_count] = fp;
			queue->memfds_count++;

			items += KDBUS_ALIGN8(it->size);
			break;
		}

		default:
			break;
		}
	}

	return 0;
}

/* add queue entry to connection, maintain priority queue */
static void kdbus_conn_queue_add(struct kdbus_conn *conn,
				 struct kdbus_conn_queue *queue)
{
	struct rb_node **n, *pn = NULL;
	bool highest = true;

	/* sort into priority queue tree */
	n = &conn->msg_prio_queue.rb_node;
	while (*n) {
		struct kdbus_conn_queue *q;

		pn = *n;
		q = rb_entry(pn, struct kdbus_conn_queue, prio_node);

		/* existing node for this priority, add to its list */
		if (likely(queue->priority == q->priority)) {
			list_add_tail(&queue->prio_entry, &q->prio_entry);
			goto prio_done;
		}

		if (queue->priority < q->priority) {
			n = &pn->rb_left;
		} else {
			n = &pn->rb_right;
			highest = false;
		}
	}

	/* cache highest-priority entry */
	if (highest)
		conn->msg_prio_highest = &queue->prio_node;

	/* new node for this priority */
	rb_link_node(&queue->prio_node, pn, n);
	rb_insert_color(&queue->prio_node, &conn->msg_prio_queue);
	INIT_LIST_HEAD(&queue->prio_entry);

prio_done:
	/* add to unsorted fifo list */
	list_add_tail(&queue->entry, &conn->msg_list);
	conn->msg_count++;
}

/* remove queue entry from connection, maintain priority queue */
static void kdbus_conn_queue_remove(struct kdbus_conn *conn,
				    struct kdbus_conn_queue *queue)
{
	list_del(&queue->entry);
	conn->msg_count--;

	/* user quota */
	if (queue->user >= 0) {
		BUG_ON(conn->msg_users[queue->user] == 0);
		conn->msg_users[queue->user]--;
		queue->user = -1;
	}

	/* the queue is empty, remove the user quota accounting */
	if (conn->msg_count == 0 && conn->msg_users_max > 0) {
		kfree(conn->msg_users);
		conn->msg_users = NULL;
		conn->msg_users_max = 0;
	}

	if (list_empty(&queue->prio_entry)) {
		/*
		 * Single entry for this priority, update cached
		 * highest-priority entry, remove the tree node.
		 */
		if (conn->msg_prio_highest == &queue->prio_node)
			conn->msg_prio_highest = rb_next(&queue->prio_node);

		rb_erase(&queue->prio_node, &conn->msg_prio_queue);
	} else {
		struct kdbus_conn_queue *q;

		/*
		 * Multiple entries for this priority entry, get next one in
		 * the list. Update cached highest-priority entry, store the
		 * new one as the tree node.
		 */
		q = list_first_entry(&queue->prio_entry,
				     struct kdbus_conn_queue, prio_entry);
		list_del(&queue->prio_entry);

		if (conn->msg_prio_highest == &queue->prio_node)
			conn->msg_prio_highest = &q->prio_node;

		rb_replace_node(&queue->prio_node, &q->prio_node,
				&conn->msg_prio_queue);
	}
}

static void kdbus_conn_queue_cleanup(struct kdbus_conn_queue *queue)
{
	kdbus_conn_memfds_unref(queue);
	kdbus_conn_fds_unref(queue);
	kfree(queue);
}

/* enqueue a message into the receiver's pool */
static int kdbus_conn_queue_alloc(struct kdbus_conn *conn,
				  const struct kdbus_kmsg *kmsg,
				  struct kdbus_conn_queue **q)
{
	struct kdbus_conn_queue *queue;
	u64 msg_size;
	size_t size;
	size_t dst_name_len = 0;
	size_t payloads = 0;
	size_t fds = 0;
	size_t meta = 0;
	size_t vec_data;
	size_t want, have;
	size_t off;
	int ret = 0;

	if (kmsg->fds && !(conn->flags & KDBUS_HELLO_ACCEPT_FD))
		return -ECOMM;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	queue->user = -1;

	/* copy message properties we need for the queue management */
	queue->src_id = kmsg->msg.src_id;
	queue->cookie = kmsg->msg.cookie;

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
		queue->dst_name_id = kmsg->dst_name_id;
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
		fds = msg_size;
		msg_size += KDBUS_ITEM_SIZE(kmsg->fds_count * sizeof(int));
	}

	/* space for metadata/credential items */
	if (kmsg->meta && kmsg->meta->size > 0 &&
	    kmsg->meta->domain == conn->meta->domain) {
		meta = msg_size;
		msg_size += kmsg->meta->size;
	}

	/* data starts after the message */
	vec_data = KDBUS_ALIGN8(msg_size);

	/* allocate the needed space in the pool of the receiver */
	mutex_lock(&conn->lock);
	if (!kdbus_conn_active(conn)) {
		ret = -ECONNRESET;
		goto exit_unlock;
	}

	/* do not give out more than half of the remaining space */
	want = vec_data + kmsg->vecs_size;
	have = kdbus_pool_remain(conn->pool);
	if (want < have && want > have / 2) {
		ret = -EXFULL;
		goto exit_unlock;
	}

	ret = kdbus_pool_alloc_range(conn->pool, want, &off);
	if (ret < 0)
		goto exit_unlock;

	/* copy the message header */
	ret = kdbus_pool_write(conn->pool, off, &kmsg->msg, size);
	if (ret < 0)
		goto exit_pool_free;

	/* update the size */
	ret = kdbus_pool_write(conn->pool, off, &msg_size,
			       sizeof(kmsg->msg.size));
	if (ret < 0)
		goto exit_pool_free;

	if (dst_name_len  > 0) {
		char tmp[KDBUS_ITEM_HEADER_SIZE + dst_name_len];
		struct kdbus_item *it = (struct kdbus_item *)tmp;

		it->size = KDBUS_ITEM_HEADER_SIZE + dst_name_len;
		it->type = KDBUS_ITEM_DST_NAME;
		memcpy(it->str, kmsg->dst_name, dst_name_len);

		ret = kdbus_pool_write(conn->pool, off + size, it, it->size);
		if (ret < 0)
			goto exit_pool_free;
	}

	/* add PAYLOAD items */
	if (payloads > 0) {
		ret = kdbus_conn_payload_add(conn, queue, kmsg,
					     off, payloads, vec_data);
		if (ret < 0)
			goto exit_pool_free;
	}

	/* add a FDS item; the array content will be updated at RECV time */
	if (kmsg->fds_count > 0) {
		char tmp[KDBUS_ITEM_HEADER_SIZE];
		struct kdbus_item *it = (struct kdbus_item *)tmp;

		it->type = KDBUS_ITEM_FDS;
		it->size = KDBUS_ITEM_HEADER_SIZE +
			   (kmsg->fds_count * sizeof(int));
		ret = kdbus_pool_write(conn->pool, off + fds,
				       it, KDBUS_ITEM_HEADER_SIZE);
		if (ret < 0)
			goto exit_pool_free;

		ret = kdbus_conn_fds_ref(queue, kmsg->fds, kmsg->fds_count);
		if (ret < 0)
			goto exit_pool_free;

		/* remember the array to update at RECV */
		queue->fds = fds + offsetof(struct kdbus_item, fds);
		queue->fds_count = kmsg->fds_count;
	}

	/* append message metadata/credential items */
	if (meta > 0) {
		ret = kdbus_pool_write(conn->pool, off + meta,
				       kmsg->meta->data, kmsg->meta->size);
		if (ret < 0)
			goto exit_pool_free;
	}

	/* copy some properties of the message to the queue entry */
	queue->off = off;
	queue->size = want;
	queue->priority = kmsg->msg.priority;
	mutex_unlock(&conn->lock);

	*q = queue;
	return 0;

exit_pool_free:
	kdbus_pool_free_range(conn->pool, off);
exit_unlock:
	mutex_unlock(&conn->lock);
	kdbus_conn_queue_cleanup(queue);
	return ret;
}

/*
 * Check for maximum number of messages per individual user. This
 * should prevent a single user from being able to fill the receiver's
 * queue.
 */
static int kdbus_conn_queue_user_quota(struct kdbus_conn *conn,
				       const struct kdbus_conn *conn_src,
				       struct kdbus_conn_queue *queue)
{
	unsigned int user;

	if (!conn_src)
		return 0;

	if (kdbus_bus_uid_is_privileged(conn->bus))
		return 0;

	/*
	 * Only after the queue grows above the maximum number of messages
	 * per individual user, we start to count all further messages
	 * from the sending users.
	 */
	if (conn->msg_count < KDBUS_CONN_MAX_MSGS_PER_USER)
		return 0;

	user = conn_src->user->idr;

	/* extend array to store the user message counters */
	if (user >= conn->msg_users_max) {
		unsigned int *users;
		unsigned int i;

		i = 8 + KDBUS_ALIGN8(user);
		users = kmalloc(sizeof(unsigned int) * i, GFP_KERNEL);
		if (!users)
			return -ENOMEM;

		memcpy(users, conn->msg_users,
		       sizeof(unsigned int) * conn->msg_users_max);
		kfree(users);
		conn->msg_users = users;
		conn->msg_users_max = i;
	}

	if (conn->msg_users[user] > KDBUS_CONN_MAX_MSGS_PER_USER)
		return -ENOBUFS;

	conn->msg_users[user]++;
	queue->user = user;
	return 0;
}

/* enqueue a message into the receiver's pool */
static int kdbus_conn_queue_insert(struct kdbus_conn *conn,
				   struct kdbus_conn *conn_src,
				   const struct kdbus_kmsg *kmsg,
				   struct kdbus_conn_reply *reply)
{
	struct kdbus_conn_queue *queue;
	int ret;

	/* limit the maximum number of queued messages */
	if (!kdbus_bus_uid_is_privileged(conn->bus) &&
	    conn->msg_count > KDBUS_CONN_MAX_MSGS)
		return -ENOBUFS;

	ret = kdbus_conn_queue_alloc(conn, kmsg, &queue);
	if (ret < 0)
		return ret;

	/* limit the number of queued messages from the same individual user */
	ret = kdbus_conn_queue_user_quota(conn, conn_src, queue);
	if (ret < 0)
		return ret;

	/*
	 * Remember the the reply associated with this queue entry, so we can
	 * move the reply entry's connection when a connection moves from an
	 * activator to an implementor.
	 */
	queue->reply = reply;

	/* link the message into the receiver's queue */
	mutex_lock(&conn->lock);
	kdbus_conn_queue_add(conn, queue);
	mutex_unlock(&conn->lock);

	/* wake up poll() */
	wake_up_interruptible(&conn->wait);

	return 0;
}

static void kdbus_conn_work(struct work_struct *work)
{
	struct kdbus_conn *conn;
	struct kdbus_conn_reply *reply, *reply_tmp;
	LIST_HEAD(notify_list);
	LIST_HEAD(reply_list);
	u64 deadline = ~0ULL;
	struct timespec ts;
	u64 now;

	ktime_get_ts(&ts);
	now = timespec_to_ns(&ts);

	conn = container_of(work, struct kdbus_conn, work.work);

	mutex_lock(&conn->lock);
	if (!kdbus_conn_active(conn)) {
		mutex_unlock(&conn->lock);
		return;
	}

	list_for_each_entry_safe(reply, reply_tmp, &conn->reply_list, entry) {
		/*
		 * If the reply block is waiting for synchronous I/O,
		 * the timeout is handled by wait_event_*_timeout(),
		 * so we don't have to care for it here.
		 */
		if (reply->sync)
			continue;

		if (reply->deadline_ns > now) {
			/* remember next timeout */
			if (deadline > reply->deadline_ns)
				deadline = reply->deadline_ns;

			continue;
		}

		/*
		 * Move to temporary cleanup list; we cannot unref and
		 * possibly cleanup a connection that is holding a ref
		 * back to us, while we are locking ourselves.
		 */
		list_move_tail(&reply->entry, &reply_list);

		/*
		 * A zero deadline means the connection died, was
		 * cleaned up already and the notify sent.
		 */
		if (reply->deadline_ns == 0)
			continue;

		kdbus_notify_reply_timeout(reply->conn->id, reply->cookie,
					   &notify_list);
	}

	/* rearm delayed work with next timeout */
	if (deadline != ~0ULL && kdbus_conn_active(conn)) {
		u64 usecs = div_u64(deadline - now, 1000ULL);

		schedule_delayed_work(&conn->work, usecs_to_jiffies(usecs));
	}
	mutex_unlock(&conn->lock);

	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);

	list_for_each_entry_safe(reply, reply_tmp, &reply_list, entry)
		kdbus_conn_reply_free(reply);
}

/* find and pin destination connection */
static int kdbus_conn_get_conn_dst(struct kdbus_bus *bus,
				   struct kdbus_kmsg *kmsg,
				   struct kdbus_conn **conn)
{
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_conn *c;
	int ret = 0;

	if (msg->dst_id == KDBUS_DST_ID_NAME) {
		const struct kdbus_name_entry *name_entry;

		BUG_ON(!kmsg->dst_name);
		name_entry = kdbus_name_lookup(bus->name_registry,
					       kmsg->dst_name);
		if (!name_entry)
			return -ESRCH;

		/*
		 * Record the sequence number of the registered name;
		 * it will be passed on to the queue, in case messages
		 * addressed to a name need to be moved from or to
		 * activator connections of the same name.
		 */
		kmsg->dst_name_id = name_entry->name_id;

		if (!name_entry->conn && name_entry->activator)
			c = kdbus_conn_ref(name_entry->activator);
		else
			c = kdbus_conn_ref(name_entry->conn);

		if ((msg->flags & KDBUS_MSG_FLAGS_NO_AUTO_START) &&
		    (c->flags & KDBUS_HELLO_ACTIVATOR)) {
			ret = -EADDRNOTAVAIL;
			goto exit_unref;
		}
	} else {
		mutex_lock(&bus->lock);
		c = kdbus_bus_find_conn_by_id(bus, msg->dst_id);
		mutex_unlock(&bus->lock);

		if (!c)
			return -ENXIO;

		/*
		 * Special-purpose connections are not allowed to be addressed
		 * via their unique IDs.
		 */
		if (c->flags & (KDBUS_HELLO_ACTIVATOR|KDBUS_HELLO_MONITOR)) {
			ret = -ENXIO;
			goto exit_unref;
		}
	}

	if (!kdbus_conn_active(c)) {
		ret = -ECONNRESET;
		goto exit_unref;
	}

	/* the connection is already ref'ed at this point */
	*conn = c;
	return 0;

exit_unref:
	kdbus_conn_unref(c);
	return ret;
}

static int kdbus_conn_fds_install(struct kdbus_conn *conn,
				  struct kdbus_conn_queue *queue)
{
	unsigned int i;
	int ret, *fds;
	size_t size;

	/* get array of file descriptors */
	size = queue->fds_count * sizeof(int);
	fds = kmalloc(size, GFP_KERNEL);
	if (!fds)
		return -ENOMEM;

	/* allocate new file descriptors in the receiver's process */
	for (i = 0; i < queue->fds_count; i++) {
		fds[i] = get_unused_fd();
		if (fds[i] < 0) {
			ret = fds[i];
			goto remove_unused;
		}
	}

	/* copy the array into the message item */
	ret = kdbus_pool_write(conn->pool, queue->off + queue->fds, fds, size);
	if (ret < 0)
		goto remove_unused;

	/* install files in the receiver's process */
	for (i = 0; i < queue->fds_count; i++)
		fd_install(fds[i], get_file(queue->fds_fp[i]));

	kfree(fds);
	return 0;

remove_unused:
	for (i = 0; i < queue->fds_count; i++) {
		if (fds[i] < 0)
			break;

		put_unused_fd(fds[i]);
	}

	kfree(fds);
	return ret;
}

static int kdbus_conn_memfds_install(struct kdbus_conn *conn,
				     struct kdbus_conn_queue *queue,
				     int **memfds)
{
	int *fds;
	unsigned int i;
	size_t size;
	int ret = 0;

	size = queue->memfds_count * sizeof(int);
	fds = kmalloc(size, GFP_KERNEL);
	if (!fds)
		return -ENOMEM;

	/* allocate new file descriptors in the receiver's process */
	for (i = 0; i < queue->memfds_count; i++) {
		fds[i] = get_unused_fd();
		if (fds[i] < 0) {
			ret = fds[i];
			goto remove_unused;
		}
	}

	/*
	 * Update the file descriptor number in the items. We remembered
	 * the locations of the values in the buffer.
	 */
	for (i = 0; i < queue->memfds_count; i++) {
		ret = kdbus_pool_write(conn->pool,
				       queue->off + queue->memfds[i],
				       &fds[i], sizeof(int));
		if (ret < 0)
			goto remove_unused;
	}

	/* install files in the receiver's process */
	for (i = 0; i < queue->memfds_count; i++)
		fd_install(fds[i], get_file(queue->memfds_fp[i]));

	*memfds = fds;
	return 0;

remove_unused:
	for (i = 0; i < queue->memfds_count; i++) {
		if (fds[i] < 0)
			break;

		put_unused_fd(fds[i]);
	}

	kfree(fds);
	*memfds = NULL;
	return ret;
}

static int kdbus_conn_msg_install(struct kdbus_conn *conn,
				  struct kdbus_conn_queue *queue)
{
	int *memfds = NULL;
	unsigned int i;
	int ret = 0;

	/*
	 * Install KDBUS_MSG_PAYLOAD_MEMFDs file descriptors, we return
	 * the list of file descriptors to be able to cleanup on error.
	 */
	if (queue->memfds_count > 0) {
		ret = kdbus_conn_memfds_install(conn, queue, &memfds);
		if (ret < 0)
			return ret;
	}

	/* install KDBUS_MSG_FDS file descriptors */
	if (queue->fds_count > 0) {
		ret = kdbus_conn_fds_install(conn, queue);
		if (ret < 0)
			goto exit_rewind;
	}

	kfree(memfds);
	kdbus_pool_flush_dcache(conn->pool, queue->off, queue->size);

	return 0;

exit_rewind:
	for (i = 0; i < queue->memfds_count; i++)
		sys_close(memfds[i]);
	kfree(memfds);

	return ret;
}

/**
 * kdbus_cmd_msg_recv() - receive a message from the queue
 * @conn:		Connection to work on
 * @recv:		The command as passed in by the ioctl
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_cmd_msg_recv(struct kdbus_conn *conn,
		       struct kdbus_cmd_recv *recv)
{
	struct kdbus_conn_queue *queue = NULL;
	LIST_HEAD(notify_list);
	int ret = 0;

	mutex_lock(&conn->lock);
	if (conn->msg_count == 0) {
		ret = -EAGAIN;
		goto exit_unlock;
	}

	if (recv->offset > 0) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	if (recv->flags & KDBUS_RECV_USE_PRIORITY) {
		/* get next message with highest priority */
		queue = rb_entry(conn->msg_prio_highest,
				 struct kdbus_conn_queue, prio_node);

		/* no entry with the requested priority */
		if (queue->priority > recv->priority) {
			ret = -ENOMSG;
			goto exit_unlock;
		}
	} else {
		/* ignore the priority, return the next entry in the queue */
		queue = list_first_entry(&conn->msg_list,
					 struct kdbus_conn_queue, entry);
	}

	BUG_ON(!queue);

	/* just drop the message */
	if (recv->flags & KDBUS_RECV_DROP) {
		struct kdbus_conn_reply *reply = NULL;

		if (queue->reply) {
			if (queue->reply->sync) {
				kdbus_conn_reply_sync(queue->reply, -EPIPE);
			} else {
				list_del(&queue->reply->entry);
				reply = queue->reply;
			}

			kdbus_notify_reply_dead(queue->src_id,
						queue->cookie, &notify_list);
		}

		kdbus_conn_queue_remove(conn, queue);
		kdbus_pool_free_range(conn->pool, queue->off);
		mutex_unlock(&conn->lock);

		if (reply)
			kdbus_conn_reply_free(reply);

		kdbus_conn_queue_cleanup(queue);

		goto exit;
	}

	/* Give the offset back to the caller. */
	recv->offset = queue->off;

	/*
	 * Just return the location of the next message. Do not install
	 * file descriptors or anything else. This is usually used to
	 * determine the sender of the next queued message.
	 *
	 * File descriptor numbers referenced in the message items
	 * are undefined, they are only valid with the full receive
	 * not with peek.
	 */
	if (recv->flags & KDBUS_RECV_PEEK) {
		kdbus_pool_flush_dcache(conn->pool, queue->off, queue->size);
		goto exit_unlock;
	}

	ret = kdbus_conn_msg_install(conn, queue);
	kdbus_conn_queue_remove(conn, queue);
	kdbus_conn_queue_cleanup(queue);

exit_unlock:
	mutex_unlock(&conn->lock);
exit:
	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);
	return ret;
}

/**
 * kdbus_cmd_msg_cancel() - cancel all pending sync requests
 *			    with the given cookie
 * @conn:		The connection
 * @cookie:		The cookie
 *
 * Return: 0 on success, or -ENOENT if no pending request with that
 * cookie was found.
 */
int kdbus_cmd_msg_cancel(struct kdbus_conn *conn,
			 u64 cookie)
{
	struct kdbus_conn_reply *reply, *reply_tmp;
	struct kdbus_conn *c;
	bool found = false;
	int i;

	if (atomic_read(&conn->reply_count) == 0)
		return -ENOENT;

	mutex_lock(&conn->bus->lock);
	hash_for_each(conn->bus->conn_hash, i, c, hentry) {
		if (c == conn)
			continue;

		mutex_lock(&c->lock);
		list_for_each_entry_safe(reply, reply_tmp,
					 &c->reply_list, entry) {
			if (reply->sync &&
			    reply->conn == conn &&
			    reply->cookie == cookie) {
				kdbus_conn_reply_sync(reply, -ECANCELED);
				found = true;
			}
		}
		mutex_unlock(&c->lock);
	}
	mutex_unlock(&conn->bus->lock);

	return found ? 0 : -ENOENT;
}

/**
 * kdbus_conn_kmsg_send() - send a message
 * @ep:			Endpoint to send from
 * @conn_src:		Connection, kernel-generated messages do not have one
 * @kmsg:		Message to send
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_conn_kmsg_send(struct kdbus_ep *ep,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn_reply *reply_wait = NULL;
	struct kdbus_conn_reply *reply_wake = NULL;
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_conn *c, *conn_dst = NULL;
	struct kdbus_bus *bus;
	bool sync;
	int ret;

	bus = ep->bus;

	mutex_lock(&bus->lock);
	if (unlikely(ep->bus->disconnected)) {
		mutex_unlock(&ep->bus->lock);
		return -ESHUTDOWN;
	}
	mutex_unlock(&bus->lock);

	sync = msg->flags & KDBUS_MSG_FLAGS_SYNC_REPLY;

	/* assign domain-global message sequence number */
	BUG_ON(kmsg->seq > 0);
	kmsg->seq = atomic64_inc_return(&bus->domain->msg_seq_last);

	/* non-kernel senders append credentials/metadata */
	if (conn_src) {
		ret = kdbus_meta_new(&kmsg->meta);
		if (ret < 0)
			return ret;
	}

	/* broadcast message */
	if (msg->dst_id == KDBUS_DST_ID_BROADCAST) {
		unsigned int i;

		mutex_lock(&bus->lock);
		hash_for_each(bus->conn_hash, i, conn_dst, hentry) {
			if (conn_dst->id == msg->src_id)
				continue;

			/*
			 * Activator connections will not receive any
			 * broadcast messages.
			 */
			if (conn_dst->flags & KDBUS_HELLO_ACTIVATOR)
				continue;

			if (!kdbus_match_db_match_kmsg(conn_dst->match_db,
						       conn_src, kmsg))
				continue;

			/*
			 * The first receiver which requests additional
			 * metadata causes the message to carry it; all
			 * receivers after that will see all of the added
			 * data, even when they did not ask for it.
			 */
			if (conn_src)
				kdbus_meta_append(kmsg->meta, conn_src,
						  kmsg->seq,
						  conn_dst->attach_flags);

			kdbus_conn_queue_insert(conn_dst, conn_src, kmsg, NULL);
		}
		mutex_unlock(&bus->lock);

		return 0;
	}

	/* direct message */
	ret = kdbus_conn_get_conn_dst(bus, kmsg, &conn_dst);
	if (ret < 0)
		return ret;

	/* For kernel-generated messages, skip the reply logic */
	if (!conn_src)
		goto meta_append;

	if (msg->flags & KDBUS_MSG_FLAGS_EXPECT_REPLY) {
		struct timespec ts;

		if (atomic_read(&conn_src->reply_count) >
		    KDBUS_CONN_MAX_REQUESTS_PENDING) {
			ret = -EMLINK;
			goto exit_unref;
		}

		/*
		 * This message expects a reply, so let's interpret
		 * msg->timeout_ns and add a kdbus_conn_reply object.
		 * Add it to the list of expected replies on the
		 * destination connection.
		 * When a reply is received later on, this entry will
		 * be used to allow the reply to pass, circumventing the
		 * policy.
		 */
		reply_wait = kzalloc(sizeof(*reply_wait), GFP_KERNEL);
		if (!reply_wait) {
			ret = -ENOMEM;
			goto exit_unref;
		}

		reply_wait->conn = kdbus_conn_ref(conn_src);
		reply_wait->cookie = msg->cookie;

		if (sync) {
			init_waitqueue_head(&reply_wait->wait);
			reply_wait->sync = true;
			reply_wait->waiting = true;
		} else {
			/* calculate the deadline based on the current time */
			ktime_get_ts(&ts);
			reply_wait->deadline_ns = timespec_to_ns(&ts) +
						  msg->timeout_ns;
		}

		mutex_lock(&conn_dst->lock);
		list_add(&reply_wait->entry, &conn_dst->reply_list);
		atomic_inc(&conn_src->reply_count);

		/*
		 * For async operation, schedule the scan now. It won't do
		 * any real work at this point, but walk the list of all
		 * pending replies and rearm the connection's delayed work
		 * to the closest entry.
		 * For synchronous operation, the timeout will be handled
		 * by wait_event_interruptible_timeout().
		 */
		if (!sync && kdbus_conn_active(conn_dst))
			schedule_delayed_work(&conn_dst->work, 0);

		mutex_unlock(&conn_dst->lock);
	} else {
		bool allowed = false;

		/*
		 * Walk the conn_src's list of expected replies.
		 * If there's any matching entry, allow the message to
		 * be sent, and remove the entry.
		 */
		if (msg->cookie_reply > 0) {
			struct kdbus_conn_reply *r, *r_tmp;
			LIST_HEAD(reply_list);

			mutex_lock(&conn_src->lock);
			list_for_each_entry_safe(r, r_tmp,
						 &conn_src->reply_list,
						 entry) {
				if (r->conn == conn_dst &&
				    r->cookie == msg->cookie_reply) {
					if (r->sync)
						reply_wake = r;
					else
						list_move_tail(&r->entry,
							       &reply_list);

					allowed = true;
					break;
				}
			}
			mutex_unlock(&conn_src->lock);

			list_for_each_entry_safe(r, r_tmp, &reply_list, entry)
				kdbus_conn_reply_free(r);
		}

		if (allowed)
			goto meta_append;

		/* ... otherwise, ask the policy DBs for permission */
		if (ep->policy_db) {
			ret = kdbus_policy_check_talk_access(ep->policy_db,
							     conn_src, conn_dst);
			if (ret < 0)
				goto exit_unref;
		}

		if (bus->policy_db) {
			ret = kdbus_policy_check_talk_access(bus->policy_db,
							     conn_src, conn_dst);
			if (ret < 0)
				goto exit_unref;
		}
	}

meta_append:
	/*
	 * A message can never be both the reply to a message and a message
	 * that waits for a reply at the same time.
	 */
	BUG_ON(reply_wait && reply_wake);

	if (conn_src) {
		ret = kdbus_meta_append(kmsg->meta, conn_src, kmsg->seq,
					conn_dst->attach_flags);
		if (ret < 0)
			goto exit_unref;
	}

	if (reply_wake) {
		/*
		 * If we're synchronously responding to a message, allocate a
		 * queue item and attach it to the reply tracking object.
		 * The connection's queue will never get to see it.
		 */
		ret = kdbus_conn_queue_alloc(conn_dst, kmsg,
					     &reply_wake->queue);

		mutex_lock(&conn_dst->lock);
		kdbus_conn_reply_sync(reply_wake, ret);
		mutex_unlock(&conn_dst->lock);
	} else {
		/*
		 * Otherwise, put it in the queue and wait for the connection
		 * to dequeue and receive the message.
		 */
		ret = kdbus_conn_queue_insert(conn_dst, conn_src,
					      kmsg, reply_wait);
	}

	if (ret < 0)
		goto exit_unref;

	/*
	 * Monitor connections get all messages; ignore possible errors
	 * when sending messages to monitor connections.
	 */
	mutex_lock(&bus->lock);
	list_for_each_entry(c, &bus->monitors_list, monitor_entry) {
		kdbus_meta_append(kmsg->meta, conn_src, kmsg->seq,
				  c->attach_flags);
		kdbus_conn_queue_insert(c, NULL, kmsg, NULL);
	}
	mutex_unlock(&bus->lock);

	if (sync) {
		int r;
		struct kdbus_conn_queue *queue;
		u64 usecs = div_u64(msg->timeout_ns, 1000ULL);

		BUG_ON(!reply_wait);

		/*
		 * Block until the reply arrives. reply_wait is left untouched
		 * by the timeout scans that might be conducted for other,
		 * asynchronous replies of conn_src.
		 */
		r = wait_event_interruptible_timeout(reply_wait->wait,
						     !reply_wait->waiting,
						     usecs_to_jiffies(usecs));
		if (r == 0)
			ret = -ETIMEDOUT;
		else if (r < 0)
			ret = -EINTR;
		else
			ret = reply_wait->err;

		/*
		 * If we weren't woken up sanely via kdbus_conn_reply_sync(),
		 * reply_wait->entry is dangling in the connection's
		 * reply_list and needs to be killed manually.
		 */
		if (r <= 0) {
			mutex_lock(&conn_dst->lock);
			list_del(&reply_wait->entry);
			mutex_unlock(&conn_dst->lock);
		}

		mutex_lock(&conn_src->lock);
		queue = reply_wait->queue;
		if (queue) {
			if (ret == 0)
				ret = kdbus_conn_msg_install(conn_src, queue);

			kmsg->msg.offset_reply = queue->off;
			kdbus_conn_queue_cleanup(queue);
		}
		mutex_unlock(&conn_src->lock);

		kdbus_conn_reply_free(reply_wait);
	}

exit_unref:
	/* conn_dst got an extra ref from kdbus_conn_get_conn_dst */
	kdbus_conn_unref(conn_dst);

	return ret;
}

/**
 * kdbus_conn_kmsg_free() - free a list of kmsg objects
 * @kmsg_list:		List head of kmsg objects to free.
 */
void kdbus_conn_kmsg_list_free(struct list_head *kmsg_list)
{
	struct kdbus_kmsg *kmsg, *tmp;

	list_for_each_entry_safe(kmsg, tmp, kmsg_list, queue_entry) {
		list_del(&kmsg->queue_entry);
		kdbus_kmsg_free(kmsg);
	}
}

/**
 * kdbus_conn_kmsg_list_send() - send a list of previously collected messages
 * @ep:			The endpoint to use for sending
 * @kmsg_list:		List head of kmsg objects to send.
 *
 * The list is cleared and freed after sending.
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_conn_kmsg_list_send(struct kdbus_ep *ep,
			      struct list_head *kmsg_list)
{
	struct kdbus_kmsg *kmsg;
	int ret = 0;

	list_for_each_entry(kmsg, kmsg_list, queue_entry) {
		ret = kdbus_conn_kmsg_send(ep, NULL, kmsg);
		if (ret < 0)
			break;
	}

	kdbus_conn_kmsg_list_free(kmsg_list);

	return ret;
}

/**
 * kdbus_conn_disconnect() - disconnect a connection
 * @conn:		The connection to disconnect
 * @ensure_queue_empty:	Flag to indicate if the call should fail in
 *			case the connection's message list is not
 *			empty
 *
 * If @ensure_msg_list_empty is true, and the connection has pending messages,
 * -EBUSY is returned.
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_conn_disconnect(struct kdbus_conn *conn, bool ensure_queue_empty)
{
	struct kdbus_conn_reply *reply, *reply_tmp;
	struct kdbus_conn_queue *queue, *tmp;
	LIST_HEAD(notify_list);
	LIST_HEAD(reply_list);

	mutex_lock(&conn->lock);
	if (!kdbus_conn_active(conn)) {
		mutex_unlock(&conn->lock);
		return -EALREADY;
	}

	if (ensure_queue_empty && !list_empty(&conn->msg_list)) {
		mutex_unlock(&conn->lock);
		return -EBUSY;
	}

	conn->disconnected = true;
	mutex_unlock(&conn->lock);

	cancel_delayed_work_sync(&conn->work);

	/* remove from bus and endpoint */
	mutex_lock(&conn->bus->lock);
	mutex_lock(&conn->ep->lock);
	hash_del(&conn->hentry);
	list_del(&conn->monitor_entry);
	list_del(&conn->ep_entry);
	mutex_unlock(&conn->ep->lock);
	mutex_unlock(&conn->bus->lock);

	/* if we die while other connections wait for our reply, notify them */
	mutex_lock(&conn->lock);
	list_for_each_entry_safe(queue, tmp, &conn->msg_list, entry) {
		if (queue->reply)
			kdbus_notify_reply_dead(queue->src_id,
						queue->cookie, &notify_list);

		kdbus_conn_queue_remove(conn, queue);
		kdbus_pool_free_range(conn->pool, queue->off);
		kdbus_conn_queue_cleanup(queue);
	}
	list_splice_init(&conn->reply_list, &reply_list);
	mutex_unlock(&conn->lock);

	list_for_each_entry_safe(reply, reply_tmp, &reply_list, entry) {
		if (reply->sync) {
			kdbus_conn_reply_sync(reply, -EPIPE);
			continue;
		}

		/*
		 * In asynchronous cases, send a 'connection
		 * dead' notification, mark entry as handled,
		 * and trigger the timeout handler.
		 */
		kdbus_notify_reply_dead(reply->conn->id, reply->cookie,
					&notify_list);

		reply->deadline_ns = 0;
		if (kdbus_conn_active(reply->conn))
			schedule_delayed_work(&reply->conn->work, 0);

		list_del(&reply->entry);
		kdbus_conn_reply_free(reply);
	}

	/* remove all names associated with this connection */
	kdbus_name_remove_by_conn(conn->bus->name_registry, conn);

	/* wake up the queue so that users can get a POLLERR */
	wake_up_interruptible(&conn->wait);

	kdbus_notify_id_change(KDBUS_ITEM_ID_REMOVE, conn->id, conn->flags,
			       &notify_list);

	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);
	return 0;
}

/**
 * kdbus_conn_active() - connection is not disconnected
 * @conn:		Connection to check
 *
 * Return: true if the connection is still active
 */
bool kdbus_conn_active(const struct kdbus_conn *conn)
{
	return !conn->disconnected;
}

static void __kdbus_conn_free(struct kref *kref)
{
	struct kdbus_conn *conn = container_of(kref, struct kdbus_conn, kref);

	kdbus_conn_disconnect(conn, false);

	atomic_dec(&conn->user->connections);
	kdbus_domain_user_unref(conn->user);

	if (conn->ep->policy_db)
		kdbus_policy_remove_conn(conn->ep->policy_db, conn);

	if (conn->bus->policy_db)
		kdbus_policy_remove_owner(conn->bus->policy_db, conn);

	kdbus_meta_free(conn->owner_meta);
	kdbus_match_db_free(conn->match_db);
	kdbus_pool_free(conn->pool);
	kdbus_ep_unref(conn->ep);
	kdbus_bus_unref(conn->bus);
	kfree(conn->name);
	kfree(conn);
}

/**
 * kdbus_conn_ref() - take a connection reference
 * @conn:		Connection
 *
 * Return: the connection itself
 */
struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn)
{
	kref_get(&conn->kref);
	return conn;
}

/**
 * kdbus_conn_unref() - drop a connection reference
 * @conn:		Connection (may be NULL)
 *
 * When the last reference is dropped, the connection's internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_conn *kdbus_conn_unref(struct kdbus_conn *conn)
{
	if (!conn)
		return NULL;

	kref_put(&conn->kref, __kdbus_conn_free);
	return NULL;
}

/**
 * kdbus_conn_move_messages() - move messages from one connection to another
 * @conn_dst:		Connection to copy to
 * @conn_src:		Connection to copy from
 * @name_id:		Filter for the sequence number of the registered
 *			name, 0 means no filtering.
 *
 * Move all messages from one connection to another. This is used when
 * an implementor connection is taking over a well-known name from an
 * activator connection.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			     struct kdbus_conn *conn_src,
			     u64 name_id)
{
	struct kdbus_conn_queue *q, *q_tmp;
	LIST_HEAD(reply_list);
	LIST_HEAD(msg_list);
	int ret = 0;

	BUG_ON(!mutex_is_locked(&conn_dst->bus->lock));
	BUG_ON(conn_src == conn_dst);

	/* remove all messages from the source */
	mutex_lock(&conn_src->lock);
	list_splice_init(&conn_src->reply_list, &reply_list);
	list_for_each_entry_safe(q, q_tmp, &conn_src->msg_list, entry) {
		kdbus_conn_queue_remove(conn_src, q);
		list_add_tail(&q->entry, &msg_list);
	}
	mutex_unlock(&conn_src->lock);

	/* insert messages into destination */
	mutex_lock(&conn_dst->lock);
	list_for_each_entry_safe(q, q_tmp, &msg_list, entry) {
		/* filter messages for a specific name */
		if (name_id > 0 && q->dst_name_id != name_id) {
			kdbus_conn_queue_cleanup(q);
			continue;
		}

		ret = kdbus_pool_move(conn_dst->pool, conn_src->pool,
				      &q->off, q->size);
		if (WARN_ON(ret < 0))
			kdbus_conn_queue_cleanup(q);
		else
			kdbus_conn_queue_add(conn_dst, q);
	}
	list_splice(&reply_list, &conn_dst->reply_list);
	mutex_unlock(&conn_dst->lock);

	/* wake up poll() */
	wake_up_interruptible(&conn_dst->wait);

	return ret;
}

/**
 * kdbus_cmd_conn_info() - retrieve info about a connection
 * @conn:		Connection
 * @cmd_info:		The command as passed in by the ioctl
 * @size:		Size of the passed data structure
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_cmd_conn_info(struct kdbus_conn *conn,
			struct kdbus_cmd_conn_info *cmd_info,
			size_t size)
{
	struct kdbus_conn *owner_conn = NULL;
	struct kdbus_conn_info info = {};
	struct kdbus_meta *meta = NULL;
	char *name = NULL;
	size_t off, pos;
	int ret = 0;
	u64 flags;
	u32 hash;

	if (cmd_info->id == 0) {
		if (size == sizeof(struct kdbus_cmd_conn_info)) {
			ret = -EINVAL;
			goto exit;
		}

		if (!kdbus_name_is_valid(cmd_info->name, false)) {
			ret = -EINVAL;
			goto exit;
		}

		name = cmd_info->name;
		hash = kdbus_str_hash(name);
	} else {
		mutex_lock(&conn->bus->lock);
		owner_conn = kdbus_bus_find_conn_by_id(conn->bus, cmd_info->id);
		mutex_unlock(&conn->bus->lock);
	}

	/*
	 * If a lookup by name was requested, set owner_conn to the
	 * matching entry's connection pointer. Otherwise, owner_conn
	 * was already set above.
	 */
	if (name) {
		struct kdbus_name_entry *e;

		if (!kdbus_check_strlen(cmd_info, name)) {
			ret = -EINVAL;
			goto exit;
		}

		e = kdbus_name_lookup(conn->bus->name_registry, name);
		if (!e) {
			ret = -ENOENT;
			goto exit;
		}

		if (e->conn)
			owner_conn = kdbus_conn_ref(e->conn);
	}

	if (!owner_conn) {
		ret = -ENXIO;
		goto exit;
	}

	info.size = sizeof(info);
	info.id = owner_conn->id;
	info.flags = owner_conn->flags;

	/* do not leak domain-specific credentials */
	if (conn->meta->domain == owner_conn->meta->domain)
		info.size += owner_conn->meta->size;

	/*
	 * Unlike the rest of the values which are cached at connection
	 * creation time, some values need to be appended here because
	 * at creation time a connection does not have names and other
	 * properties.
	 */
	flags = cmd_info->flags & (KDBUS_ATTACH_NAMES | KDBUS_ATTACH_CONN_NAME);
	if (flags) {
		ret = kdbus_meta_new(&meta);
		if (ret < 0)
			goto exit;

		ret = kdbus_meta_append(meta, owner_conn, 0, flags);
		if (ret < 0)
			goto exit;

		info.size += meta->size;
	}

	ret = kdbus_pool_alloc_range(conn->pool, info.size, &off);
	if (ret < 0)
		goto exit;

	ret = kdbus_pool_write(conn->pool, off, &info, sizeof(info));
	if (ret < 0)
		goto exit_free;

	pos = off + sizeof(info);

	if (conn->meta->domain == owner_conn->meta->domain) {
		ret = kdbus_pool_write(conn->pool, pos, owner_conn->meta->data,
				       owner_conn->meta->size);
		if (ret < 0)
			goto exit_free;

		pos += owner_conn->meta->size;
	}

	if (meta) {
		ret = kdbus_pool_write(conn->pool, pos, meta->data, meta->size);
		if (ret < 0)
			goto exit_free;
	}

	/* write back the offset */
	cmd_info->offset = off;
	kdbus_pool_flush_dcache(conn->pool, off, info.size);

exit_free:
	if (ret < 0)
		kdbus_pool_free_range(conn->pool, off);

exit:
	kdbus_meta_free(meta);
	kdbus_conn_unref(owner_conn);

	return ret;
}

/**
 * kdbus_conn_update() - update flags for a connection
 * @conn:		Connection
 * @cmd:		The command as passed in by the ioctl
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_cmd_conn_update(struct kdbus_conn *conn,
			  const struct kdbus_cmd_update *cmd)
{
	const struct kdbus_item *item;
	bool policy_provided = false;
	int ret;

	KDBUS_ITEMS_FOREACH(item, cmd->items, KDBUS_ITEMS_SIZE(cmd, items)) {
		switch (item->type) {
		case KDBUS_ITEM_ATTACH_FLAGS:
			conn->attach_flags = item->data64[0];
			break;
		case KDBUS_ITEM_NAME:
		case KDBUS_ITEM_POLICY_ACCESS:
			policy_provided = true;
			break;
		}
	}

	if (!policy_provided)
		return 0;

	if (!conn->bus->policy_db) {
		ret = kdbus_policy_db_new(&conn->bus->policy_db);
		if (ret < 0)
			return ret;
	}

	ret = kdbus_policy_set(conn->bus->policy_db, cmd->items,
			       KDBUS_ITEMS_SIZE(cmd, items),
			       1, false, conn);

	return ret;
}

/**
 * kdbus_conn_new() - create a new connection
 * @ep:			The endpoint the connection is connected to
 * @hello:		The kdbus_cmd_hello as passed in by the user
 * @meta:		The metadata gathered at open() time of the handle
 * @c:			Returned connection
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_conn_new(struct kdbus_ep *ep,
		   struct kdbus_cmd_hello *hello,
		   struct kdbus_meta *meta,
		   struct kdbus_conn **c)
{
	const struct kdbus_creds *creds = NULL;
	const struct kdbus_item *item;
	const char *conn_name = NULL;
	const char *seclabel = NULL;
	const char *name = NULL;
	struct kdbus_conn *conn;
	struct kdbus_bus *bus;
	size_t seclabel_len = 0;
	LIST_HEAD(notify_list);
	bool is_policy_holder;
	bool is_activator;
	bool is_monitor;
	int ret;

	bus = ep->bus;

	BUG_ON(*c);

	is_monitor = hello->conn_flags & KDBUS_HELLO_MONITOR;
	is_activator = hello->conn_flags & KDBUS_HELLO_ACTIVATOR;
	is_policy_holder = hello->conn_flags & KDBUS_HELLO_POLICY_HOLDER;

	/* can't be activator or policy holder and monitor at the same time */
	if (is_monitor && (is_activator || is_policy_holder))
		return -EINVAL;

	/* can't be policy holder and activator at the same time */
	if (is_activator && is_policy_holder)
		return -EINVAL;

	/* only privileged connections can activate and monitor */
	if (!kdbus_bus_uid_is_privileged(bus) &&
	    (is_activator || is_policy_holder || is_monitor))
		return -EPERM;

	KDBUS_ITEMS_FOREACH(item, hello->items, KDBUS_ITEMS_SIZE(hello, items)) {
		switch (item->type) {
		case KDBUS_ITEM_NAME:
			if (!is_activator && !is_policy_holder)
				return -EINVAL;

			if (name)
				return -EINVAL;

			if (!kdbus_item_validate_nul(item))
				return -EINVAL;

			if (!kdbus_name_is_valid(item->str, true))
				return -EINVAL;

			name = item->str;
			break;

		case KDBUS_ITEM_CREDS:
			/* privileged processes can impersonate somebody else */
			if (!kdbus_bus_uid_is_privileged(bus))
				return -EPERM;

			if (item->size != KDBUS_ITEM_SIZE(sizeof(*creds)))
				return -EINVAL;

			creds = &item->creds;
			break;

		case KDBUS_ITEM_SECLABEL:
			/* privileged processes can impersonate somebody else */
			if (!kdbus_bus_uid_is_privileged(bus))
				return -EPERM;

			if (!kdbus_item_validate_nul(item))
				return -EINVAL;

			seclabel = item->str;
			seclabel_len = item->size - KDBUS_ITEM_HEADER_SIZE;
			break;

		case KDBUS_ITEM_CONN_NAME:
			/* human-readable connection name (debugging) */
			if (conn_name)
				return -EINVAL;

			ret = kdbus_item_validate_name(item);
			if (ret < 0)
				return ret;

			conn_name = item->str;
			break;
		}
	}

	if ((is_activator || is_policy_holder) && !name)
		return -EINVAL;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	if (is_activator || is_policy_holder) {
		if (!bus->policy_db) {
			ret = kdbus_policy_db_new(&bus->policy_db);
			if (ret < 0)
				goto exit_free_conn;
		}

		/*
		 * Policy holders may install any number of names, and
		 * are allowed to use wildcards as well.
		 */
		ret = kdbus_policy_set(bus->policy_db, hello->items,
				       KDBUS_ITEMS_SIZE(hello, items),
				       is_policy_holder ? 0 : 1,
				       is_policy_holder, conn);
		if (ret < 0)
			goto exit_free_conn;
	}

	if (conn_name) {
		conn->name = kstrdup(conn_name, GFP_KERNEL);
		if (!conn->name) {
			ret = -ENOMEM;
			goto exit_free_conn;
		}
	}

	kref_init(&conn->kref);
	mutex_init(&conn->lock);
	INIT_LIST_HEAD(&conn->msg_list);
	conn->msg_prio_queue = RB_ROOT;
	INIT_LIST_HEAD(&conn->names_list);
	INIT_LIST_HEAD(&conn->names_queue_list);
	INIT_LIST_HEAD(&conn->reply_list);
	atomic_set(&conn->reply_count, 0);
	INIT_DELAYED_WORK(&conn->work, kdbus_conn_work);
	conn->cred = current_cred();
	init_waitqueue_head(&conn->wait);

	/* init entry, so we can unconditionally remove it */
	INIT_LIST_HEAD(&conn->monitor_entry);

	ret = kdbus_pool_new(conn->name, hello->pool_size, &conn->pool);
	if (ret < 0)
		goto exit_free_conn;

	ret = kdbus_match_db_new(&conn->match_db);
	if (ret < 0)
		goto exit_free_pool;

	conn->bus = kdbus_bus_ref(ep->bus);
	conn->ep = kdbus_ep_ref(ep);

	/* get new id for this connection */
	conn->id = atomic64_inc_return(&bus->conn_seq_last);

	/* return properties of this connection to the caller */
	hello->bus_flags = bus->bus_flags;
	hello->bloom = bus->bloom;
	hello->id = conn->id;

	BUILD_BUG_ON(sizeof(bus->id128) != sizeof(hello->id128));
	memcpy(hello->id128, bus->id128, sizeof(hello->id128));

	conn->flags = hello->conn_flags;
	conn->attach_flags = hello->attach_flags;

	/* notify about the new active connection */
	ret = kdbus_notify_id_change(KDBUS_ITEM_ID_ADD, conn->id, conn->flags,
				     &notify_list);
	if (ret < 0)
		goto exit_unref_ep;
	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);

	if (is_activator) {
		u64 flags = KDBUS_NAME_ACTIVATOR;

		ret = kdbus_name_acquire(bus->name_registry, conn,
					 name, &flags, NULL);
		if (ret < 0)
			goto exit_free_pool;
	}

	if (is_monitor) {
		mutex_lock(&bus->lock);
		list_add_tail(&conn->monitor_entry, &bus->monitors_list);
		mutex_unlock(&bus->lock);
	}

	/* privileged processes can impersonate somebody else */
	if (creds || seclabel) {
		ret = kdbus_meta_new(&conn->owner_meta);
		if (ret < 0)
			goto exit_release_names;

		if (creds) {
			ret = kdbus_meta_append_data(conn->owner_meta,
					KDBUS_ITEM_CREDS,
					creds, sizeof(struct kdbus_creds));
			if (ret < 0)
				goto exit_free_meta;
		}

		if (seclabel) {
			ret = kdbus_meta_append_data(conn->owner_meta,
						     KDBUS_ITEM_SECLABEL,
						     seclabel, seclabel_len);
			if (ret < 0)
				goto exit_free_meta;
		}

		/* use the information provided with the HELLO call */
		conn->meta = conn->owner_meta;
	} else {
		/* use the connection's metadata gathered at open() */
		conn->meta = meta;
	}

	/*
	 * Account the connection against the current user (UID), or for
	 * custom endpoints use the anonymous user assigned to the endpoint.
	 */
	if (ep->user)
		conn->user = kdbus_domain_user_ref(ep->user);
	else
		conn->user = kdbus_domain_user_find_or_new(ep->bus->domain,
							   current_fsuid());
	if (!conn->user) {
		ret = -ENOMEM;
		goto exit_free_meta;
	}

	if (!capable(CAP_IPC_OWNER) &&
	    atomic_inc_return(&conn->user->connections) > KDBUS_USER_MAX_CONN) {
		atomic_dec(&conn->user->connections);
		ret = -EMFILE;
		goto exit_unref_user;
	}

	/* link into bus and endpoint */
	mutex_lock(&bus->lock);
	mutex_lock(&ep->lock);
	if (bus->disconnected || ep->disconnected) {
		mutex_unlock(&ep->lock);
		mutex_unlock(&bus->lock);
		ret = -ESHUTDOWN;
		goto exit_unref_user;
	}
	list_add_tail(&conn->ep_entry, &ep->conn_list);
	hash_add(bus->conn_hash, &conn->hentry, conn->id);
	mutex_unlock(&ep->lock);
	mutex_unlock(&bus->lock);

	*c = conn;
	return 0;

exit_unref_user:
	kdbus_domain_user_unref(conn->user);
exit_free_meta:
	kdbus_meta_free(conn->owner_meta);
exit_release_names:
	kdbus_name_remove_by_conn(bus->name_registry, conn);
exit_unref_ep:
	kdbus_ep_unref(conn->ep);
	kdbus_bus_unref(conn->bus);
	kdbus_match_db_free(conn->match_db);
exit_free_pool:
	kdbus_pool_free(conn->pool);
exit_free_conn:
	kfree(conn->name);
	kfree(conn);

	return ret;
}

/**
 * kdbus_conn_has_name() - check if a connection owns a name
 * @conn:		Connection
 * @name:		Well-know name to check for
 *
 * Return: true if the name is currently owned by the connection
 */
bool kdbus_conn_has_name(struct kdbus_conn *conn, const char *name)
{
	struct kdbus_name_entry *e;
	bool match = false;

	mutex_lock(&conn->lock);
	list_for_each_entry(e, &conn->names_list, conn_entry) {
		if (strcmp(e->name, name) == 0) {
			match = true;
			break;
		}
	}
	mutex_unlock(&conn->lock);

	return match;
}
