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

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include "connection.h"
#include "message.h"
#include "memfd.h"
#include "notify.h"
#include "namespace.h"
#include "endpoint.h"
#include "bus.h"
#include "match.h"
#include "names.h"
#include "policy.h"
#include "metadata.h"

/**
 * struct kdbus_conn_queue - messages waiting to be read
 * @entry:		Entry in the connection's list
 * @off:		Offset into the shmem file in the receiver's pool
 * @size:		The number of bytes used in the pool
 * @memfds:		Arrays of offsets where to update the installed fd number
 * @memfds_fp:		Array memfd files queued up for this message
 * @memfds_count:	Number of memfds
 * @fds:		Offset to array where to update the installed fd number
 * @fds_fp:		Array passed files queued up for this message
 * @fds_count:		Number of files
 * @deadline_ns:	Timeout for this message, used for replies
 * @src_id:		The ID of the sender
 * @cookie:		Message cookie, used for replies
 */
struct kdbus_conn_queue {
	struct list_head entry;
	size_t off;
	size_t size;

	size_t *memfds;
	struct file **memfds_fp;
	unsigned int memfds_count;

	size_t fds;
	struct file **fds_fp;
	unsigned int fds_count;

	u64 deadline_ns;
	u64 src_id;
	u64 cookie;
};

/**
 * struct kdbus_conn_reply_entry - an entry of kdbus_conn's list of replies
 * @entry:		The list_head entry of the connection's reply_from_list
 * @conn:		The counterpart connection that is expected to answer
 * @deadline_ns:	The deadline of the reply, in nanoseconds
 * @cookie:		The expected reply cookie
 */
struct kdbus_conn_reply_entry {
	struct list_head entry;
	struct kdbus_conn *conn;
	u64 deadline_ns;
	u64 cookie;
};

static void kdbus_conn_reply_entry_free(struct kdbus_conn_reply_entry *reply)
{
	atomic_dec(&reply->conn->reply_count);
	kdbus_conn_unref(reply->conn);
	list_del(&reply->entry);
	kfree(reply);
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

	queue->fds_fp = kmalloc(fds_count * sizeof(struct file *), GFP_KERNEL);
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
		size_t size;

		size = kmsg->memfds_count * sizeof(size_t);
		queue->memfds = kmalloc(size, GFP_KERNEL);
		if (!queue->memfds)
			return -ENOMEM;

		size = kmsg->memfds_count * sizeof(struct file *);
		queue->memfds_fp = kzalloc(size, GFP_KERNEL);
		if (!queue->memfds_fp)
			return -ENOMEM;
	}

	KDBUS_ITEM_FOREACH(item, &kmsg->msg, items) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			const size_t size = KDBUS_ITEM_HEADER_SIZE +
					    sizeof(struct kdbus_vec);
			char tmp[size];
			struct kdbus_item *it = (struct kdbus_item *)tmp;

			/* add item */
			it->type = KDBUS_ITEM_PAYLOAD_OFF;
			it->size = size;

			/* a NULL address specifies a \0-bytes record */
			if (KDBUS_PTR(item->vec.address))
				it->vec.offset = off + vec_data;
			else
				it->vec.offset = ~0ULL;
			it->vec.size = item->vec.size;
			ret = kdbus_pool_write(conn->pool, off + items, it, size);
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
				kdbus_pool_write_user(conn->pool, off + vec_data,
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
			const size_t size = KDBUS_ITEM_HEADER_SIZE +
					    sizeof(struct kdbus_memfd);
			char tmp[size];
			struct kdbus_item *it = (struct kdbus_item *)tmp;
			struct file *fp;
			size_t memfd;

			/* add item */
			it->type = KDBUS_ITEM_PAYLOAD_MEMFD;
			it->size = size;
			it->memfd.size = item->memfd.size;
			it->memfd.fd = -1;
			ret = kdbus_pool_write(conn->pool, off + items, it, size);
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

			items += KDBUS_ALIGN8((it)->size);
			break;
		}

		default:
			break;
		}
	}

	return 0;
}

static void kdbus_conn_queue_cleanup(struct kdbus_conn_queue *queue)
{
	kdbus_conn_memfds_unref(queue);
	kdbus_conn_fds_unref(queue);
	kfree(queue);
}

/* enqueue a message into the receiver's pool */
static int kdbus_conn_queue_insert(struct kdbus_conn *conn,
				   struct kdbus_kmsg *kmsg,
				   u64 deadline_ns)
{
	struct kdbus_conn_queue *queue;
	u64 msg_size;
	size_t size;
	size_t payloads = 0;
	size_t fds = 0;
	size_t meta = 0;
	size_t vec_data;
	size_t want, have;
	size_t off;
	int ret = 0;

	if (kmsg->fds && !(conn->flags & KDBUS_HELLO_ACCEPT_FD))
		return -ECOMM;

	queue = kzalloc(sizeof(struct kdbus_conn_queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	/* copy message properties we need for the queue management */
	queue->deadline_ns = deadline_ns;
	queue->src_id = kmsg->msg.src_id;
	queue->cookie = kmsg->msg.cookie;

	/* space for the header */
	if (kmsg->msg.src_id == KDBUS_SRC_ID_KERNEL)
		size = kmsg->msg.size;
	else
		size = offsetof(struct kdbus_msg, items);
	msg_size = size;

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
	if (kmsg->meta.size > 0 && kmsg->meta.ns == conn->meta.ns) {
		meta = msg_size;
		msg_size += kmsg->meta.size;
	}

	/* data starts after the message */
	vec_data = KDBUS_ALIGN8(msg_size);

	/* allocate the needed space in the pool of the receiver */
	mutex_lock(&conn->lock);
	if (conn->disconnected) {
		ret = -ECONNRESET;
		goto exit_unlock;
	}

	if (!capable(CAP_IPC_OWNER) &&
	    conn->msg_count > KDBUS_CONN_MAX_MSGS) {
		ret = -ENOBUFS;
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
		goto exit_unlock;

	/* update the size */
	ret = kdbus_pool_write(conn->pool, off, &msg_size, sizeof(kmsg->msg.size));
	if (ret < 0)
		goto exit_unlock;

	/* add PAYLOAD items */
	if (payloads > 0) {
		ret = kdbus_conn_payload_add(conn, queue, kmsg,
					     off, payloads, vec_data);
		if (ret < 0)
			goto exit_unlock;
	}

	/* add a FDS item; the array content will be updated at RECV time */
	if (kmsg->fds_count > 0) {
		const size_t size = KDBUS_ITEM_HEADER_SIZE;
		char tmp[size];
		struct kdbus_item *it = (struct kdbus_item *)tmp;

		it->type = KDBUS_ITEM_FDS;
		it->size = size + (kmsg->fds_count * sizeof(int));
		ret = kdbus_pool_write(conn->pool, off + fds, it, size);
		if (ret < 0)
			goto exit_unlock;

		ret = kdbus_conn_fds_ref(queue, kmsg->fds, kmsg->fds_count);
		if (ret < 0)
			goto exit_unlock;

		/* remember the array to update at RECV */
		queue->fds = fds + offsetof(struct kdbus_item, fds);
		queue->fds_count = kmsg->fds_count;
	}

	/* append message metadata/credential items */
	if (meta > 0) {
		ret = kdbus_pool_write(conn->pool, off + meta,
				       kmsg->meta.data, kmsg->meta.size);
		if (ret < 0)
			goto exit_unlock;
	}

	/* remember the offset to the message */
	queue->off = off;
	queue->size = want;

	/* link the message into the receiver's queue */
	list_add_tail(&queue->entry, &conn->msg_list);
	conn->msg_count++;

	mutex_unlock(&conn->lock);

	/* wake up poll() */
	wake_up_interruptible(&conn->ep->wait);
	return 0;

exit_unlock:
	mutex_unlock(&conn->lock);
	kdbus_conn_queue_cleanup(queue);
	kdbus_pool_free_range(conn->pool, off);
	return ret;
}

static void kdbus_conn_scan_timeout(struct kdbus_conn *conn)
{
	struct kdbus_conn_queue *queue, *queue_tmp;
	struct kdbus_conn_reply_entry *reply, *reply_tmp;
	LIST_HEAD(notify_list);
	u64 deadline = -1;
	struct timespec ts;
	u64 now;

	ktime_get_ts(&ts);
	now = timespec_to_ns(&ts);

	mutex_lock(&conn->lock);
	list_for_each_entry_safe(queue, queue_tmp, &conn->msg_list, entry) {
		if (queue->deadline_ns == 0)
			continue;

		if (queue->deadline_ns <= now) {
			kdbus_pool_free_range(conn->pool, queue->off);
			list_del(&queue->entry);
			kdbus_conn_queue_cleanup(queue);
		} else if (queue->deadline_ns < deadline) {
			deadline = queue->deadline_ns;
		}
	}

	list_for_each_entry_safe(reply, reply_tmp, &conn->reply_list, entry) {
		if (reply->deadline_ns <= now) {
			kdbus_notify_reply_timeout(conn->ep, reply->conn->id,
						   reply->cookie, &notify_list);
			//FIXME: conn->lock is held, but entry_free might
			//       call disconnect which takes it too
			kdbus_conn_reply_entry_free(reply);
		}
	}
	mutex_unlock(&conn->lock);

	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);

	if (deadline != -1) {
		u64 usecs = deadline - now;
		do_div(usecs, 1000ULL);
		mod_timer(&conn->timer, jiffies + usecs_to_jiffies(usecs));
	}
}

static void kdbus_conn_work(struct work_struct *work)
{
	struct kdbus_conn *conn = container_of(work, struct kdbus_conn, work);

	kdbus_conn_scan_timeout(conn);
}

static void kdbus_conn_timeout_schedule_scan(struct kdbus_conn *conn)
{
	schedule_work(&conn->work);
}

static void kdbus_conn_timer_func(unsigned long val)
{
	struct kdbus_conn *conn = (struct kdbus_conn *) val;
	kdbus_conn_timeout_schedule_scan(conn);
}

/* find and pin destination connection */
static int kdbus_conn_get_conn_dst(struct kdbus_bus *bus,
				   const struct kdbus_kmsg *kmsg,
				   struct kdbus_conn **conn)
{
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_conn *c;
	bool disconnected;
	int ret = 0;

	if (msg->dst_id == KDBUS_DST_ID_NAME) {
		const struct kdbus_name_entry *name_entry;

		BUG_ON(!kmsg->dst_name);
		name_entry = kdbus_name_lookup(bus->name_registry,
					       kmsg->dst_name);
		if (!name_entry)
			return -ESRCH;

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
		 * A activator connection is not allowed to be addressed
		 * via its unique id.
		 */
		if (c->flags & KDBUS_HELLO_ACTIVATOR) {
			ret = -ENXIO;
			goto exit_unref;
		}
	}

	mutex_lock(&c->lock);
	disconnected = c->disconnected;
	mutex_unlock(&c->lock);

	if (disconnected) {
		ret = -ECONNRESET;
		goto exit_unref;
	}

	/* the connection is already ref'ed at this point */
	*conn = c;

	/* nullify it so it won't be freed below */
	c = NULL;

exit_unref:
	kdbus_conn_unref(c);

	return ret;
}

/**
 * kdbus_conn_kmsg_send() - send a message
 * @ep:			Endpoint to send from
 * @conn_src:		Connection, kernel-generated messages do not have one
 * @kmsg:		Message to send
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_conn_kmsg_send(struct kdbus_ep *ep,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg)
{
	const struct kdbus_msg *msg = &kmsg->msg;
	struct kdbus_conn *conn_dst = NULL;
	struct kdbus_conn *conn;
	u64 deadline_ns = 0;
	int ret;

	/* broadcast message */
	if (msg->dst_id == KDBUS_DST_ID_BROADCAST) {
		unsigned int i;

		mutex_lock(&ep->bus->lock);
		hash_for_each(ep->bus->conn_hash, i, conn_dst, hentry) {
			bool disconnected = false;

			if (conn_dst->id == msg->src_id)
				continue;

			/*
			 * activator connections will not receive any
			 * broadcast messages.
			 */
			if (conn_dst->flags & KDBUS_HELLO_ACTIVATOR)
				continue;

			if (!kdbus_match_db_match_kmsg(conn_dst->match_db,
						       conn_src, kmsg))
				continue;

			mutex_lock(&conn_dst->lock);
			disconnected = conn_dst->disconnected;
			mutex_unlock(&conn_dst->lock);

			if (unlikely(disconnected))
				continue;

			/*
			 * The first receiver which requests additional
			 * metadata causes the message to carry it; all
			 * receivers after that will see all of the added
			 * data, even when they did not ask for it.
			 */
			kdbus_meta_append(&kmsg->meta, conn_src, NULL,
					  conn_dst->attach_flags);

			kdbus_conn_queue_insert(conn_dst, kmsg, 0);
		}
		mutex_unlock(&ep->bus->lock);

		return 0;
	}

	/* direct message */
	ret = kdbus_conn_get_conn_dst(ep->bus, kmsg, &conn_dst);
	if (ret < 0)
		return ret;

	if (conn_src) {
		bool allowed = false;
		struct kdbus_conn_reply_entry *reply;

		/*
		 * Walk the list of connection we expect a reply from.
		 * If there's any matching entry, allow the message to
		 * be sent, and remove the entry.
		 */
		mutex_lock(&conn_dst->lock);
		list_for_each_entry(reply, &conn_dst->reply_list, entry) {
			if (reply->conn == conn_src &&
			    reply->cookie == msg->cookie_reply) {
				kdbus_conn_reply_entry_free(reply);
				allowed = true;
				break;
			}
		}
		mutex_unlock(&conn_dst->lock);

		/* ... otherwise, ask the policy DB for permission */
		if (!allowed && ep->policy_db) {
			ret = kdbus_policy_db_check_send_access(ep->policy_db,
								conn_src,
								conn_dst);
			if (ret < 0)
				goto exit_unref;
		}
	}

	/*
	 * If the message has a timeout value set, calculate the deadline here,
	 * based on the current time. Note that this only takes care for the
	 * timeout of the actual message, and has nothing to do with a potential
	 * reply that may be expected.
	 */
	if (msg->src_id != KDBUS_SRC_ID_KERNEL && msg->timeout_ns > 0) {
		struct timespec ts;

		ktime_get_ts(&ts);
		deadline_ns = timespec_to_ns(&ts) + msg->timeout_ns;
	}

	/* If the message expects a reply, add a kdbus_conn_reply_entry */
	if (conn_src && (msg->flags & KDBUS_MSG_FLAGS_EXPECT_REPLY)) {
		struct kdbus_conn_reply_entry *reply;

		reply = kzalloc(sizeof(*reply), GFP_KERNEL);
		if (!reply) {
			ret = -ENOMEM;
			goto exit_unref;
		}

		INIT_LIST_HEAD(&reply->entry);
		reply->deadline_ns = deadline_ns;
		reply->conn = kdbus_conn_ref(conn_dst);
		atomic_inc(&reply->conn->reply_count);
		reply->cookie = msg->cookie;

		mutex_lock(&conn_src->lock);
		list_add(&reply->entry, &conn_src->reply_list);
		mutex_unlock(&conn_src->lock);
	}

	ret = kdbus_meta_append(&kmsg->meta, conn_src, NULL,
				conn_dst->attach_flags);
	if (ret < 0)
		goto exit_unref;

	/* Eaves-dropping (monitor) connections get all messages */
	mutex_lock(&ep->bus->lock);
	list_for_each_entry(conn, &ep->bus->monitors_list, monitor_entry) {
		/* the monitor connection is addressed, deliver it below */
		if (conn->id == conn_dst->id)
			continue;

		/* ignore errors of misbehaving monitor connections */
		kdbus_conn_queue_insert(conn, kmsg, 0);
	}
	mutex_unlock(&ep->bus->lock);

	ret = kdbus_conn_queue_insert(conn_dst, kmsg, deadline_ns);
	if (ret < 0)
		goto exit_unref;

	if (deadline_ns > 0)
		kdbus_conn_timeout_schedule_scan(conn_dst);

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
 * Returns 0 on success.
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

static int kdbus_conn_fds_install(struct kdbus_conn *conn,
				  struct kdbus_conn_queue *queue)
{
	size_t size;
	unsigned int i;
	int *fds;
	int ret;

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
	size_t size;
	int *fds;
	unsigned int i;
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

/**
 * kdbus_conn_recv_msg - receive a message from the queue
 * @conn:		Connection to receive from
 * @buf:		The returned offset to the message in the pool
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_conn_recv_msg(struct kdbus_conn *conn, __u64 __user *buf)
{
	struct kdbus_conn_queue *queue;
	u64 off;
	int *memfds = NULL;
	unsigned int i;
	int ret;

	mutex_lock(&conn->lock);
	if (unlikely(conn->ep->disconnected)) {
		ret = -ECONNRESET;
		goto exit_unlock;
	}

	if (conn->msg_count == 0) {
		ret = -EAGAIN;
		goto exit_unlock;
	}

	/* return the address of the next message in the pool */
	queue = list_first_entry(&conn->msg_list,
				 struct kdbus_conn_queue, entry);

	off = queue->off;
	if (copy_to_user(buf, &off, sizeof(__u64))) {
		ret = -EFAULT;
		goto exit_unlock;
	}

	/*
	 * Install KDBUS_MSG_PAYLOAD_MEMFDs file descriptors, we return
	 * the list of file descriptors to be able to cleanup on error.
	 */
	if (queue->memfds_count > 0) {
		ret = kdbus_conn_memfds_install(conn, queue, &memfds);
		if (ret < 0)
			goto exit_unlock;
	}

	/* install KDBUS_MSG_FDS file descriptors */
	if (queue->fds_count > 0) {
		ret = kdbus_conn_fds_install(conn, queue);
		if (ret < 0)
			goto exit_rewind;
	}

	kfree(memfds);

	conn->msg_count--;
	list_del(&queue->entry);
	mutex_unlock(&conn->lock);

	kdbus_pool_flush_dcache(conn->pool, queue->off, queue->size);
	kdbus_conn_queue_cleanup(queue);
	return 0;

exit_rewind:
	for (i = 0; i < queue->memfds_count; i++)
		sys_close(memfds[i]);
	kfree(memfds);

exit_unlock:
	mutex_unlock(&conn->lock);
	return ret;
}

void kdbus_conn_disconnect(struct kdbus_conn *conn)
{
	struct kdbus_conn_queue *queue, *tmp;
	struct kdbus_bus *bus;
	LIST_HEAD(notify_list);

	mutex_lock(&conn->lock);
	if (conn->disconnected) {
		mutex_unlock(&conn->lock);
		return;
	}

	conn->disconnected = true;
	mutex_unlock(&conn->lock);

	bus = conn->ep->bus;

	/* remove from bus */
	mutex_lock(&bus->lock);
	hash_del(&conn->hentry);
	list_del(&conn->monitor_entry);
	mutex_unlock(&bus->lock);

	/* clean up any messages still left on this endpoint */
	mutex_lock(&conn->lock);
	list_for_each_entry_safe(queue, tmp, &conn->msg_list, entry) {
		if (queue->src_id > 0)
			kdbus_notify_reply_dead(conn->ep, queue->src_id,
						queue->cookie, &notify_list);

		list_del(&queue->entry);
		kdbus_pool_free_range(conn->pool, queue->off);
		kdbus_conn_queue_cleanup(queue);
	}
	mutex_unlock(&conn->lock);

	/* if we die while other connections wait for our reply, notify them */
	if (unlikely(atomic_read(&conn->reply_count) > 0)) {
		struct kdbus_conn *c;
		int i;
		struct kdbus_conn_reply_entry *reply, *reply_tmp;

		mutex_lock(&bus->lock);
		hash_for_each(bus->conn_hash, i, c, hentry) {

			mutex_lock(&c->lock);
			list_for_each_entry_safe(reply, reply_tmp, &c->reply_list, entry) {
				if (conn != reply->conn)
					continue;

				kdbus_notify_reply_dead(conn->ep, c->id,
							reply->cookie,
							&notify_list);
			}
			mutex_unlock(&c->lock);
		}
		mutex_unlock(&bus->lock);
	}

	kdbus_notify_id_change(conn->ep, KDBUS_ITEM_ID_REMOVE,
			       conn->id, conn->flags, &notify_list);
	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);

	del_timer(&conn->timer);
	cancel_work_sync(&conn->work);
	kdbus_name_remove_by_conn(bus->name_registry, conn);
}

static void __kdbus_conn_free(struct kref *kref)
{
	struct kdbus_conn *conn = container_of(kref, struct kdbus_conn, kref);
	struct kdbus_conn_reply_entry *reply, *reply_tmp;

	kdbus_conn_disconnect(conn);
	if (conn->ep->policy_db)
		kdbus_policy_db_remove_conn(conn->ep->policy_db, conn);

	list_for_each_entry_safe(reply, reply_tmp, &conn->reply_list, entry)
		kdbus_conn_reply_entry_free(reply);

	kdbus_match_db_free(conn->match_db);
	kdbus_meta_free(&conn->meta);
	kdbus_pool_free(conn->pool);
	kdbus_ep_unref(conn->ep);
	kfree(conn);
}

/**
 * kdbus_conn_ref() - take a connection reference
 * @conn:		Connection
 *
 * Returns: the connection itself
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
 * Returns: NULL
 */
struct kdbus_conn *kdbus_conn_unref(struct kdbus_conn *conn)
{
	if (!conn)
		return NULL;

	kref_put(&conn->kref, __kdbus_conn_free);
	return NULL;
}

/**
 * kdbus_conn_move_messages() - move a message from one connection to another
 * @conn_dst:		Connection to copy to
 * @conn_src:		Connection to copy from
 *
 * Move all messages from one connection to another. This is used when
 * an ordinary connection is taking over a well-known name from a
 * activator connection.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_conn_move_messages(struct kdbus_conn *conn_dst,
			     struct kdbus_conn *conn_src)
{
	struct kdbus_conn_queue *queue, *tmp;
	LIST_HEAD(msg_list);
	int ret = 0;

	if (!(conn_src->flags & KDBUS_HELLO_ACTIVATOR))
		return -EINVAL;

	if (conn_src == conn_dst)
		return -EINVAL;

	mutex_lock(&conn_src->lock);
	list_splice_init(&conn_src->msg_list, &msg_list);
	conn_src->msg_count = 0;
	mutex_unlock(&conn_src->lock);

	mutex_lock(&conn_dst->lock);
	list_for_each_entry_safe(queue, tmp, &msg_list, entry) {
		ret = kdbus_pool_move(conn_dst->pool, conn_src->pool,
				      &queue->off, queue->size);
		if (ret < 0)
			goto exit_unlock_dst;

		list_add_tail(&queue->entry, &conn_dst->msg_list);
		conn_dst->msg_count++;
	}

exit_unlock_dst:
	mutex_unlock(&conn_dst->lock);

	wake_up_interruptible(&conn_dst->ep->wait);

	return ret;
}

/**
 * kdbus_cmd_conn_info() - retrieve info about a connection
 * @conn:		Connection
 * @buf:		The returned offset to the message in the pool
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_cmd_conn_info(struct kdbus_conn *conn,
			void __user *buf)
{
	struct kdbus_cmd_conn_info *cmd_info;
	struct kdbus_conn_info info = {};
	struct kdbus_conn *owner_conn = NULL;
	size_t off, pos;
	char *name = NULL;
	struct kdbus_meta meta = {};
	u64 size;
	u32 hash;
	int ret = 0;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_conn_info))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_conn_info))
		return -EINVAL;

	if (size > sizeof(struct kdbus_cmd_conn_info) + KDBUS_NAME_MAX_LEN + 1)
		return -EMSGSIZE;

	cmd_info = memdup_user(buf, size);
	if (IS_ERR(cmd_info))
		return PTR_ERR(cmd_info);

	if (cmd_info->id != 0) {
		struct kdbus_bus *bus = conn->ep->bus;

		mutex_lock(&bus->lock);
		owner_conn = kdbus_bus_find_conn_by_id(bus, cmd_info->id);
		mutex_unlock(&bus->lock);
	} else {
		if (size == sizeof(struct kdbus_cmd_conn_info)) {
			ret = -EINVAL;
			goto exit_free;
		}

		if (!kdbus_name_is_valid(cmd_info->name)) {
			ret = -EINVAL;
			goto exit_free;
		}

		name = cmd_info->name;
		hash = kdbus_str_hash(name);
	}

	/*
	 * If a lookup by name was requested, set owner_conn to the
	 * matching entry's connection pointer. Otherwise, owner_conn
	 * was already set above.
	 */
	if (name) {
		struct kdbus_name_entry *e;

		e = kdbus_name_lookup(conn->ep->bus->name_registry, name);
		if (!e) {
			ret = -ENOENT;
			goto exit_free;
		}

		if (e->conn)
			owner_conn = kdbus_conn_ref(e->conn);
	}

	if (!owner_conn) {
		ret = -ENXIO;
		goto exit_free;
	}

	info.size = sizeof(struct kdbus_conn_info);
	info.id = owner_conn->id;
	info.flags = owner_conn->flags;

	/* do not leak namespace-specific credentials */
	if (conn->meta.ns == owner_conn->meta.ns)
		info.size += owner_conn->meta.size;

	/*
	 * Unlike the rest of the values which are cached at
	 * connection creation time, the names are appended here
	 * because at creation time a connection does not have
	 * any name.
	 */
	if (cmd_info->flags & KDBUS_ATTACH_NAMES &&
	    !(owner_conn->flags & KDBUS_HELLO_ACTIVATOR)) {
		ret = kdbus_meta_append(&meta, owner_conn, NULL,
					KDBUS_ATTACH_NAMES);
		if (ret < 0)
			goto exit_unref_owner_conn;

		info.size += meta.size;
	}

	ret = kdbus_pool_alloc_range(conn->pool, info.size, &off);
	if (ret < 0)
		goto exit_unref_owner_conn;

	ret = kdbus_pool_write(conn->pool, off, &info, sizeof(info));
	if (ret < 0)
		goto exit_free;
	pos = off + sizeof(struct kdbus_conn_info);

	if (conn->meta.ns == owner_conn->meta.ns) {
		ret = kdbus_pool_write(conn->pool, pos, owner_conn->meta.data,
				       owner_conn->meta.size);
		if (ret < 0)
			goto exit_free;
		pos += owner_conn->meta.size;
	}

	if (meta.size > 0) {
		ret = kdbus_pool_write(conn->pool, pos, meta.data, meta.size);
		if (ret < 0)
			goto exit_free;

		pos += meta.size;
	}

	if (kdbus_offset_set_user(&off, buf, struct kdbus_cmd_conn_info)) {
		ret = -EFAULT;
		goto exit_free;
	}

exit_free:
	if (ret < 0)
		kdbus_pool_free_range(conn->pool, off);

exit_unref_owner_conn:
	kdbus_meta_free(&meta);
	kdbus_conn_unref(owner_conn);
	kfree(cmd_info);

	return ret;
}

/**
 * kdbus_conn_new() - create a new connection
 * @ep:			The endpoint the connection is connected to
 * @hello:		The kdbus_cmd_hello as passed in by the user
 * @c:			Returned connection
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_conn_new(struct kdbus_ep *ep,
		   struct kdbus_cmd_hello *hello,
		   struct kdbus_conn **c)
{
	struct kdbus_conn *conn;
	struct kdbus_bus *bus = ep->bus;
	const struct kdbus_item *item;
	const char *activator_name = NULL;
	LIST_HEAD(notify_list);
	int ret;

	KDBUS_ITEM_FOREACH(item, hello, items) {
		switch (item->type) {
		case KDBUS_ITEM_ACTIVATOR_NAME:
			if (!(hello->conn_flags & KDBUS_HELLO_ACTIVATOR))
				return -EINVAL;

			if (activator_name)
				return -EINVAL;
			activator_name = item->str;
			break;

		default:
			return -ENOTSUPP;
		}
	}

	if ((hello->conn_flags & KDBUS_HELLO_ACTIVATOR) && !activator_name)
		return -EINVAL;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	kref_init(&conn->kref);
	mutex_init(&conn->lock);
	INIT_LIST_HEAD(&conn->msg_list);
	INIT_LIST_HEAD(&conn->names_list);
	INIT_LIST_HEAD(&conn->names_queue_list);
	INIT_LIST_HEAD(&conn->monitor_entry);
	INIT_LIST_HEAD(&conn->reply_list);
	atomic_set(&conn->reply_count, 0);
	INIT_WORK(&conn->work, kdbus_conn_work);
	init_timer(&conn->timer);
	conn->timer.expires = 0;
	conn->timer.function = kdbus_conn_timer_func;
	conn->timer.data = (unsigned long) conn;
	add_timer(&conn->timer);

	ret = kdbus_pool_new(&conn->pool, hello->pool_size);
	if (ret < 0)
		goto exit_unref;

	ret = kdbus_match_db_new(&conn->match_db);
	if (ret < 0)
		goto exit_unref;

	conn->ep = kdbus_ep_ref(ep);

	/* link into bus; get new id for this connection */
	mutex_lock(&bus->lock);
	conn->id = bus->conn_id_next++;
	hash_add(bus->conn_hash, &conn->hentry, conn->id);
	mutex_unlock(&bus->lock);

	/* return properties of this connection to the caller */
	hello->bus_flags = bus->bus_flags;
	hello->bloom_size = bus->bloom_size;
	hello->id = conn->id;

	BUILD_BUG_ON(sizeof(bus->id128) != sizeof(hello->id128));
	memcpy(hello->id128, bus->id128, sizeof(hello->id128));

	/* cache the metadata/credentials of the creator of the connection */
	ret = kdbus_meta_append(&conn->meta, conn, NULL,
				KDBUS_ATTACH_CREDS |
				KDBUS_ATTACH_COMM |
				KDBUS_ATTACH_EXE |
				KDBUS_ATTACH_CMDLINE |
				KDBUS_ATTACH_CGROUP |
				KDBUS_ATTACH_CAPS |
				KDBUS_ATTACH_SECLABEL |
				KDBUS_ATTACH_AUDIT);
	if (ret < 0)
		goto exit_unref;

	/* notify about the new active connection */
	ret = kdbus_notify_id_change(conn->ep, KDBUS_ITEM_ID_ADD,
				     conn->id, conn->flags,
				     &notify_list);
	if (ret < 0)
		goto exit_unref;
	kdbus_conn_kmsg_list_send(conn->ep, &notify_list);

	conn->flags = hello->conn_flags;
	conn->attach_flags = hello->attach_flags;

	if (activator_name) {
		ret = kdbus_name_acquire(bus->name_registry, conn,
					 activator_name, 0, NULL);
		if (ret < 0)
			goto exit_unref;
	}

	*c = conn;
	return 0;

exit_unref:
	kdbus_conn_unref(conn);
	return ret;
}
