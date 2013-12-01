/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

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
#include <linux/highmem.h>
#include <linux/syscalls.h>
#include <linux/uio.h>
#include <uapi/linux/major.h>

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

struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn);
void kdbus_conn_unref(struct kdbus_conn *conn);

struct kdbus_conn_queue {
	struct list_head entry;

	/* offset to the message placed in the receiver's buffer */
	size_t off;
	size_t size;

	/* passed KDBUS_MSG_PAYLOAD_MEMFD */
	size_t *memfds;
	struct file **memfds_fp;
	unsigned int memfds_count;

	/* passed KDBUS_MSG_FDS */
	size_t fds;
	struct file **fds_fp;
	unsigned int fds_count;

	/* timeout in the queue */
	u64 deadline_ns;
	u64 src_id;
	u64 cookie;
	bool expect_reply;
};

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

	/* We only accept kdbus_memfd files as payload, other files need to
	 * be passed with KDBUS_MSG_FDS. */
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

	KDBUS_PART_FOREACH(item, &kmsg->msg, items) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			const size_t size = KDBUS_PART_HEADER_SIZE +
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

				/* Preserve the alignment for the next payload
				 * record in the output buffer; write as many
				 * null-bytes to the buffer which the \0-bytes
				 * record would have shifted the alignment */
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
			const size_t size = KDBUS_PART_HEADER_SIZE +
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

			/* remember the file and the location of the fd number
			 * which will be updated at RECV time */
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

void kdbus_conn_queue_cleanup(struct kdbus_conn_queue *queue)
{
	kdbus_conn_memfds_unref(queue);
	kdbus_conn_fds_unref(queue);
	kfree(queue);
}

/* enqueue a message into the receiver's pool */
int kdbus_conn_queue_insert(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg,
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

	if (!conn->type == KDBUS_CONN_EP_CONNECTED)
		return -ENOTCONN;

	if (kmsg->fds && !(conn->flags & KDBUS_HELLO_ACCEPT_FD))
		return -ECOMM;

	queue = kzalloc(sizeof(struct kdbus_conn_queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	INIT_LIST_HEAD(&queue->entry);

	/* copy message properties we need for the queue management */
	queue->deadline_ns = deadline_ns;
	queue->src_id = kmsg->msg.src_id;
	queue->cookie = kmsg->msg.cookie;
	if (kmsg->msg.flags & KDBUS_MSG_FLAGS_EXPECT_REPLY)
		queue->expect_reply = true;

	/* we accept items from kernel-created messages */
	if (kmsg->msg.src_id == KDBUS_SRC_ID_KERNEL)
		size = kmsg->msg.size;
	else
		size = KDBUS_MSG_HEADER_SIZE;

	/* the header */
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
	if (kmsg->meta.size > 0) {
		meta = msg_size;
		msg_size += kmsg->meta.size;
	}

	/* data starts after the message */
	vec_data = KDBUS_ALIGN8(msg_size);

	/* allocate the needed space in the pool of the receiver */
	mutex_lock(&conn->lock);
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

	ret = kdbus_pool_alloc(conn->pool, want, &off);
	if (ret < 0)
		goto exit_unlock;
	mutex_unlock(&conn->lock);

	/* copy the message header */
	ret = kdbus_pool_write(conn->pool, off, &kmsg->msg, size);
	if (ret < 0)
		goto exit;

	/* update the size */
	ret = kdbus_pool_write(conn->pool, off, &msg_size, sizeof(kmsg->msg.size));
	if (ret < 0)
		goto exit;

	/* add PAYLOAD items */
	if (kmsg->vecs_count + kmsg->memfds_count > 0) {
		ret = kdbus_conn_payload_add(conn, queue, kmsg,
					     off, payloads, vec_data);
		if (ret < 0)
			goto exit;
	}

	/* add a FDS item; the array content will be updated at RECV time */
	if (kmsg->fds_count > 0) {
		const size_t size = KDBUS_PART_HEADER_SIZE;
		char tmp[size];
		struct kdbus_item *it = (struct kdbus_item *)tmp;

		it->type = KDBUS_ITEM_FDS;
		it->size = size + (kmsg->fds_count * sizeof(int));
		ret = kdbus_pool_write(conn->pool, off + fds, it, size);
		if (ret < 0)
			goto exit;

		ret = kdbus_conn_fds_ref(queue, kmsg->fds, kmsg->fds_count);
		if (ret < 0)
			goto exit;

		/* remember the array to update at RECV */
		queue->fds = fds + offsetof(struct kdbus_item, fds);
		queue->fds_count = kmsg->fds_count;
	}

	/* append message metadata/credential items */
	if (kmsg->meta.size > 0) {
		ret = kdbus_pool_write(conn->pool, off + meta,
				       kmsg->meta.data, kmsg->meta.size);
		if (ret < 0)
			goto exit;
	}

	/* remember the offset to the message */
	queue->off = off;
	queue->size = want;

	/* link the message into the receiver's queue */
	mutex_lock(&conn->lock);
	list_add_tail(&queue->entry, &conn->msg_list);
	conn->msg_count++;
	mutex_unlock(&conn->lock);

	/* wake up poll() */
	wake_up_interruptible(&conn->ep->wait);
	return 0;

exit_unlock:
	mutex_unlock(&conn->lock);
exit:
	kdbus_conn_queue_cleanup(queue);
	kdbus_pool_free(conn->pool, off);
	return ret;
}

static void kdbus_conn_scan_timeout(struct kdbus_conn *conn)
{
	struct kdbus_conn_queue *queue, *tmp;
	u64 deadline = -1;
	struct timespec ts;
	u64 now;

	ktime_get_ts(&ts);
	now = timespec_to_ns(&ts);

	mutex_lock(&conn->lock);
	list_for_each_entry_safe(queue, tmp, &conn->msg_list, entry) {
		if (queue->deadline_ns == 0)
			continue;

		if (queue->deadline_ns <= now) {
			if (queue->expect_reply)
				kdbus_notify_reply_timeout(conn->ep,
					queue->src_id, queue->cookie);
			kdbus_pool_free(conn->pool, queue->off);
			list_del(&queue->entry);
			kdbus_conn_queue_cleanup(queue);
		} else if (queue->deadline_ns < deadline) {
			deadline = queue->deadline_ns;
		}
	}
	mutex_unlock(&conn->lock);

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
	int ret = 0;

	mutex_lock(&bus->lock);

	if (msg->dst_id == KDBUS_DST_ID_WELL_KNOWN_NAME) {
		const struct kdbus_name_entry *name_entry;

		name_entry = kdbus_name_lookup(bus->name_registry,
					       kmsg->dst_name);
		if (!name_entry) {
			ret = -ESRCH;
			goto exit_unlock;
		}

		if (name_entry->starter)
			c = name_entry->starter;
		else
			c = name_entry->conn;

		if ((msg->flags & KDBUS_MSG_FLAGS_NO_AUTO_START) &&
		    (c->flags & KDBUS_HELLO_STARTER)) {
			ret = -EADDRNOTAVAIL;
			goto exit_unlock;
		}
	} else {
		c = kdbus_bus_find_conn_by_id(bus, msg->dst_id);
		if (!c) {
			ret = -ENXIO;
			goto exit_unlock;
		}
	}

	kdbus_conn_ref(c);
	*conn = c;

exit_unlock:
	mutex_unlock(&bus->lock);
	return ret;
}

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
			if (conn_dst->type != KDBUS_CONN_EP_CONNECTED)
				continue;

			if (conn_dst->id == msg->src_id)
				continue;

			if (!kdbus_match_db_match_kmsg(conn_dst->match_db,
						       conn_src, kmsg))
				continue;

			/* The first receiver which requests additional
			 * metadata causes the message to carry it; all
			 * receivers after that will see all of the added
			 * data, even when they did not ask for it. */
			kdbus_meta_append(&kmsg->meta, conn_src, conn_dst->attach_flags);

			kdbus_conn_queue_insert(conn_dst, kmsg, 0);
		}
		mutex_unlock(&ep->bus->lock);

		return 0;
	}

	/* direct message */
	ret = kdbus_conn_get_conn_dst(ep->bus, kmsg, &conn_dst);
	if (ret < 0)
		return ret;

	if (msg->timeout_ns) {
		struct timespec ts;

		ktime_get_ts(&ts);
		deadline_ns = timespec_to_ns(&ts) + msg->timeout_ns;
	}

	if (ep->policy_db && conn_src) {
		ret = kdbus_policy_db_check_send_access(ep->policy_db,
							conn_src,
							conn_dst,
							deadline_ns);
		if (ret < 0)
			goto exit;
	}

	ret = kdbus_meta_append(&kmsg->meta, conn_src, conn_dst->attach_flags);
	if (ret < 0)
		goto exit;

	/* the monitor connections get all messages */
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
		goto exit;

	if (msg->timeout_ns)
		kdbus_conn_timeout_schedule_scan(conn_dst);

exit:
	kdbus_conn_unref(conn_dst);
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

	/* Update the file descriptor number in the items. We remembered
	 * the locations of the values in the buffer. */
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

static int
kdbus_conn_recv_msg(struct kdbus_conn *conn, __u64 __user *buf)
{
	struct kdbus_conn_queue *queue;
	u64 off;
	int *memfds = NULL;
	unsigned int i;
	int ret;

	mutex_lock(&conn->lock);
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

	/* Install KDBUS_MSG_PAYLOAD_MEMFDs file descriptors, we return
	 * the list of file descriptors to be able to cleanup on error. */
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

int kdbus_conn_accounting_add_size(struct kdbus_conn *conn, size_t size)
{
	int ret = 0;

	if (!conn)
		return 0;

	mutex_lock(&conn->accounting_lock);
	if (conn->allocated_size + size > KDBUS_CONN_MAX_ALLOCATED_BYTES)
		ret = -EXFULL;
	else
		conn->allocated_size += size;
	mutex_unlock(&conn->accounting_lock);

	return ret;
}

void kdbus_conn_accounting_sub_size(struct kdbus_conn *conn, size_t size)
{
	if (!conn)
		return;

	mutex_lock(&conn->accounting_lock);
	conn->allocated_size -= size;
	mutex_unlock(&conn->accounting_lock);
}

/* kdbus file operations */
static int kdbus_conn_open(struct inode *inode, struct file *file)
{
	struct kdbus_conn *conn;
	struct kdbus_ns *ns;
	struct kdbus_ep *ep;
	int ret;

	conn = kzalloc(sizeof(struct kdbus_conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	kref_init(&conn->kref);

	/* find and reference namespace */
	ns = kdbus_ns_find_by_major(MAJOR(inode->i_rdev));
	if (!ns) {
		kfree(conn);
		return -ESHUTDOWN;
	}
	conn->ns = kdbus_ns_ref(ns);
	file->private_data = conn;

	/* control device node */
	if (MINOR(inode->i_rdev) == 0) {
		conn->type = KDBUS_CONN_CONTROL;
		return 0;
	}

	/* find endpoint for device node */
	mutex_lock(&conn->ns->lock);
	ep = idr_find(&conn->ns->idr, MINOR(inode->i_rdev));
	if (!ep || ep->disconnected) {
		ret = -ESHUTDOWN;
		goto exit_unlock;
	}

	/* create endpoint connection */
	conn->type = KDBUS_CONN_EP;
	conn->ep = kdbus_ep_ref(ep);
	mutex_unlock(&conn->ns->lock);
	return 0;

exit_unlock:
	mutex_unlock(&conn->ns->lock);
	kfree(conn);
	return ret;
}

static void kdbus_conn_cleanup(struct kdbus_conn *conn)
{
	struct kdbus_conn_queue *queue, *tmp;
	struct list_head list;

	INIT_LIST_HEAD(&list);

	/* remove from bus */
	mutex_lock(&conn->ep->bus->lock);
	hash_del(&conn->hentry);
	list_del(&conn->monitor_entry);
	conn->type = KDBUS_CONN_EP_DISCONNECTED;
	mutex_unlock(&conn->ep->bus->lock);

	/* clean up any messages still left on this endpoint */
	mutex_lock(&conn->lock);
	list_for_each_entry_safe(queue, tmp, &conn->msg_list, entry) {
		list_del(&queue->entry);

		/* we cannot hold "lock" and enqueue new messages with
		 * kdbus_notify_reply_dead(); move these messages
		 * into a temporary list and handle them below */
		if (queue->src_id != conn->id && queue->expect_reply) {
			list_add_tail(&queue->entry, &list);
		} else {
			kdbus_pool_free(conn->pool, queue->off);
			kdbus_conn_queue_cleanup(queue);
		}
	}
	mutex_unlock(&conn->lock);

	list_for_each_entry_safe(queue, tmp, &list, entry) {
		kdbus_notify_reply_dead(conn->ep, queue->src_id,
					queue->cookie);
		mutex_lock(&conn->lock);
		kdbus_pool_free(conn->pool, queue->off);
		mutex_unlock(&conn->lock);
		kdbus_conn_queue_cleanup(queue);
	}

	del_timer(&conn->timer);
	cancel_work_sync(&conn->work);
	kdbus_name_remove_by_conn(conn->ep->bus->name_registry, conn);
	if (conn->ep->policy_db)
		kdbus_policy_db_remove_conn(conn->ep->policy_db, conn);
	kdbus_match_db_unref(conn->match_db);
	kdbus_ep_unref(conn->ep);

	kdbus_meta_free(&conn->meta);
	kdbus_pool_cleanup(conn->pool);
}

static void __kdbus_conn_free(struct kref *kref)
{
	struct kdbus_conn *conn = container_of(kref, struct kdbus_conn, kref);

	kfree(conn);
}

struct kdbus_conn *kdbus_conn_ref(struct kdbus_conn *conn)
{
	kref_get(&conn->kref);
	return conn;
}

void kdbus_conn_unref(struct kdbus_conn *conn)
{
	kref_put(&conn->kref, __kdbus_conn_free);
}

static int kdbus_conn_release(struct inode *inode, struct file *file)
{
	struct kdbus_conn *conn = file->private_data;

	switch (conn->type) {
	case KDBUS_CONN_CONTROL_NS_OWNER:
		kdbus_ns_disconnect(conn->ns_owner);
		kdbus_ns_unref(conn->ns_owner);
		break;

	case KDBUS_CONN_CONTROL_BUS_OWNER:
		kdbus_bus_disconnect(conn->bus_owner);
		kdbus_bus_unref(conn->bus_owner);
		break;

	case KDBUS_CONN_EP_OWNER:
		kdbus_ep_disconnect(conn->ep);
		kdbus_ep_unref(conn->ep);
		break;

	case KDBUS_CONN_EP_CONNECTED:
		kdbus_notify_id_change(conn->ep, KDBUS_ITEM_ID_REMOVE,
				       conn->id, conn->flags);
		kdbus_conn_cleanup(conn);
		break;

	default:
		break;
	}

	kdbus_ns_unref(conn->ns);
	kdbus_conn_unref(conn);
	return 0;
}

static bool kdbus_check_flags(u64 kernel_flags)
{
	/* The higher 32bit are considered 'incompatible
	 * flags'. Refuse them all for now */
	return kernel_flags <= 0xFFFFFFFFULL;
}

/* kdbus control device commands */
static long kdbus_conn_ioctl_control(struct file *file, unsigned int cmd,
				     void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_bus_kmake *bus_kmake = NULL;
	struct kdbus_cmd_ns_kmake *ns_kmake = NULL;
	struct kdbus_bus *bus = NULL;
	struct kdbus_ns *ns = NULL;
	umode_t mode = 0600;
	int ret;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE: {
		kgid_t gid = KGIDT_INIT(0);

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_bus_make_user(buf, &bus_kmake);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(bus_kmake->make.flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (bus_kmake->make.flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (bus_kmake->make.flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		ret = kdbus_bus_new(conn->ns, bus_kmake, mode, current_fsuid(),
				    gid, &bus);
		if (ret < 0)
			break;

		/* turn the control fd into a new bus owner device */
		conn->type = KDBUS_CONN_CONTROL_BUS_OWNER;
		conn->bus_owner = bus;
		break;
	}

	case KDBUS_CMD_NS_MAKE:
		if (!capable(CAP_IPC_OWNER)) {
			ret = -EPERM;
			break;
		}

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_ns_kmake_user(buf, &ns_kmake);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(ns_kmake->make.flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (ns_kmake->make.flags & KDBUS_MAKE_ACCESS_WORLD)
			mode = 0666;

		ret = kdbus_ns_new(kdbus_ns_init, ns_kmake->name, mode, &ns);
		if (ret < 0)
			break;

		/* turn the control fd into a new ns owner device */
		conn->type = KDBUS_CONN_CONTROL_NS_OWNER;
		conn->ns_owner = ns;
		break;

	case KDBUS_CMD_MEMFD_NEW: {
		int fd;
		int __user *addr = buf;

		ret = kdbus_memfd_new(&fd);
		if (ret < 0)
			break;

		if (put_user(fd, addr))
			ret = -EFAULT;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(bus_kmake);
	kfree(ns_kmake);
	return ret;
}

/* kdbus endpoint make commands */
static long kdbus_conn_ioctl_ep(struct file *file, unsigned int cmd,
				void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_ep_kmake *kmake = NULL;
	struct kdbus_cmd_hello *hello = NULL;
	struct kdbus_bus *bus = conn->ep->bus;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_EP_MAKE: {
		umode_t mode = 0;
		kgid_t gid = KGIDT_INIT(0);

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_ep_kmake_user(buf, &kmake);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(kmake->make.flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (kmake->make.flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (kmake->make.flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		ret = kdbus_ep_new(conn->ep->bus, kmake->name, mode,
			current_fsuid(), gid,
			kmake->make.flags & KDBUS_MAKE_POLICY_OPEN);

		conn->type = KDBUS_CONN_EP_OWNER;
		break;
	}

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
		const struct kdbus_item *item;
		const char *starter_name = NULL;
		size_t size;
		void *v;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_hello)) {
			ret = -EFAULT;
			break;
		}

		if (size < sizeof(struct kdbus_cmd_hello) ||
		    size > KDBUS_HELLO_MAX_SIZE) {
			ret = -EMSGSIZE;
			break;
		}

		v = memdup_user(buf, size);
		if (IS_ERR(v)) {
			ret = PTR_ERR(v);
			break;
		}
		hello = v;

		if (!kdbus_check_flags(hello->conn_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (hello->pool_size == 0 ||
		    !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_pool_init(&conn->pool, hello->pool_size);
		if (ret < 0)
			break;

		KDBUS_PART_FOREACH(item, hello, items) {
			switch (item->type) {
			case KDBUS_ITEM_STARTER_NAME:
				if (!hello->conn_flags & KDBUS_HELLO_STARTER) {
					ret = -EINVAL;
					break;
				}

				starter_name = item->str;
				break;

			default:
				ret = -EINVAL;
				break;
			}

			if (ret < 0)
				break;
		}

		if (ret < 0)
			break;

		mutex_init(&conn->lock);
		mutex_init(&conn->names_lock);
		mutex_init(&conn->accounting_lock);
		INIT_LIST_HEAD(&conn->msg_list);
		INIT_LIST_HEAD(&conn->names_list);
		INIT_LIST_HEAD(&conn->names_queue_list);
		INIT_LIST_HEAD(&conn->monitor_entry);

		INIT_WORK(&conn->work, kdbus_conn_work);

		init_timer(&conn->timer);
		conn->timer.expires = 0;
		conn->timer.function = kdbus_conn_timer_func;
		conn->timer.data = (unsigned long) conn;
		add_timer(&conn->timer);

		conn->match_db = kdbus_match_db_new();

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

		ret = kdbus_meta_append(&conn->meta, conn,
					KDBUS_ATTACH_CREDS |
					KDBUS_ATTACH_NAMES |
					KDBUS_ATTACH_COMM |
					KDBUS_ATTACH_EXE |
					KDBUS_ATTACH_CMDLINE |
					KDBUS_ATTACH_CGROUP |
					KDBUS_ATTACH_CAPS |
					KDBUS_ATTACH_SECLABEL |
					KDBUS_ATTACH_AUDIT);
		if (ret < 0) {
			kdbus_conn_cleanup(conn);
			break;
		}

		if (copy_to_user(buf, hello, sizeof(struct kdbus_cmd_hello))) {
			kdbus_conn_cleanup(conn);
			ret = -EFAULT;
			break;
		}

		/* notify about the new active connection */
		ret = kdbus_notify_id_change(conn->ep, KDBUS_ITEM_ID_ADD,
					     conn->id, conn->flags);
		if (ret < 0) {
			kdbus_conn_cleanup(conn);
			break;
		}

		if (starter_name) {
			ret = kdbus_name_acquire(bus->name_registry, conn,
					         starter_name,
						 KDBUS_HELLO_STARTER, NULL);
			if (ret < 0) {
				kdbus_conn_cleanup(conn);
				break;
			}
		}

		conn->flags = hello->conn_flags;
		conn->attach_flags = hello->attach_flags;
		conn->type = KDBUS_CONN_EP_CONNECTED;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(kmake);
	kfree(hello);

	return ret;
}

/* kdbus endpoint commands for connected peers */
static long kdbus_conn_ioctl_ep_connected(struct file *file, unsigned int cmd,
					  void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_bus *bus = conn->ep->bus;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_EP_POLICY_SET:
		/* upload a policy for this endpoint */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		if (!conn->ep->policy_db)
			conn->ep->policy_db = kdbus_policy_db_new();
		if (!conn->ep->policy_db)
			return -ENOMEM;

		ret = kdbus_cmd_policy_set_from_user(conn->ep->policy_db, buf);
		break;

	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_name_acquire(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_name_release(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_NAME_LIST:
		/* return all current well-known names */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_name_list(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_NAME_INFO:
		/* return details about a specific well-known name */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_name_info(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_match_db_add(conn, buf);
		break;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_match_db_remove(conn, buf);
		break;

	case KDBUS_CMD_MONITOR: {
		/* turn on/turn off monitor mode */
		struct kdbus_cmd_monitor cmd_monitor;
		struct kdbus_conn *mconn = conn;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		if (copy_from_user(&cmd_monitor, buf, sizeof(cmd_monitor))) {
			ret = -EFAULT;
			break;
		}

		/* privileged users can act on behalf of someone else */
		if (cmd_monitor.id == 0) {
			mconn = conn;
		} else if (cmd_monitor.id != conn->id) {
			if (!kdbus_bus_uid_is_privileged(bus)) {
				ret = -EPERM;
				break;
			}

			mconn = kdbus_bus_find_conn_by_id(bus, cmd_monitor.id);
			if (!mconn) {
				ret = -ENXIO;
				break;
			}
		}

		mutex_lock(&bus->lock);
		if (cmd_monitor.flags && KDBUS_MONITOR_ENABLE)
			list_add_tail(&mconn->monitor_entry, &bus->monitors_list);
		else
			list_del(&mconn->monitor_entry);
		mutex_unlock(&bus->lock);
		break;
	}

	case KDBUS_CMD_MSG_SEND: {
		/* submit a message which will be queued in the receiver */
		struct kdbus_kmsg *kmsg;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_kmsg_new_from_user(conn, buf, &kmsg);
		if (ret < 0)
			break;

		ret = kdbus_conn_kmsg_send(conn->ep, conn, kmsg);
		kdbus_kmsg_free(kmsg);
		break;
	}

	case KDBUS_CMD_MSG_RECV: {
		/* receive a pointer to a queued message */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_conn_recv_msg(conn, buf);
		break;
	}

	case KDBUS_CMD_FREE: {
		u64 off;

		/* free the memory used in the receiver's pool */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		if (copy_from_user(&off, buf, sizeof(__u64))) {
			ret = -EFAULT;
			break;
		}

		mutex_lock(&conn->lock);
		ret = kdbus_pool_free(conn->pool, off);
		mutex_unlock(&conn->lock);
		break;
	}

	case KDBUS_CMD_MEMFD_NEW: {
		int fd;
		int __user *addr = buf;

		ret = kdbus_memfd_new(&fd);
		if (ret < 0)
			break;

		if (put_user(fd, addr))
			ret = -EFAULT;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static long kdbus_conn_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct kdbus_conn *conn = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (conn->type) {
	case KDBUS_CONN_CONTROL:
		return kdbus_conn_ioctl_control(file, cmd, argp);

	case KDBUS_CONN_EP:
		return kdbus_conn_ioctl_ep(file, cmd, argp);

	case KDBUS_CONN_EP_CONNECTED:
		return kdbus_conn_ioctl_ep_connected(file, cmd, argp);

	default:
		return -EBADFD;
	}
}

static unsigned int kdbus_conn_poll(struct file *file,
				    struct poll_table_struct *wait)
{
	struct kdbus_conn *conn = file->private_data;
	unsigned int mask = 0;

	/* Only an endpoint can read/write data */
	if (conn->type != KDBUS_CONN_EP_CONNECTED)
		return POLLERR | POLLHUP;

	poll_wait(file, &conn->ep->wait, wait);

	mutex_lock(&conn->lock);
	if (unlikely(conn->ep->disconnected))
		mask |= POLLERR | POLLHUP;
	else if (!list_empty(&conn->msg_list))
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&conn->lock);

	return mask;
}

static int kdbus_conn_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kdbus_conn *conn = file->private_data;

	if (conn->flags & KDBUS_HELLO_STARTER)
		return -EPERM;

	return kdbus_pool_mmap(conn->pool, vma);
}

const struct file_operations kdbus_device_ops = {
	.owner =		THIS_MODULE,
	.open =			kdbus_conn_open,
	.release =		kdbus_conn_release,
	.poll =			kdbus_conn_poll,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	kdbus_conn_ioctl,
	.mmap =			kdbus_conn_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		kdbus_conn_ioctl,
#endif
};
