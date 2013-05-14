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
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>
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
	if (!is_kdbus_memfd(fp)) {
		ret = -EMEDIUMTYPE;
		goto exit_unref;
	}

	/* We only accept a sealed memfd file whose content cannot be altered
	 * by the sender or anybody else while it is shared or in-flight. */
	if (!is_kdbus_memfd_sealed(fp)) {
		ret = -ETXTBSY;
		goto exit_unref;
	}

	/* The specified size in the item cannot be larger than the file. */
	if (item->memfd.size > kdbus_memfd_size(fp)) {
		return -EBADF;
		goto exit_unref;
	}

	*file = fp;
	return 0;

exit_unref:
	fput(fp);
	return ret;
}

static int kdbus_conn_payload_add(struct kdbus_conn_queue *queue,
				  const struct kdbus_kmsg *kmsg,
				  struct task_struct *task,
				  struct kdbus_item __user *items,
				  void __user *vec_data)
{
	struct kdbus_pool_map pool_map;
	const struct kdbus_item *item;
	int ret;

	if (kmsg->vecs_count > 0) {
		ret = kdbus_pool_map_open(&pool_map, task,
					  vec_data,
					  kmsg->vecs_size);
		if (ret < 0)
			return ret;
	}

	if (kmsg->memfds_count > 0) {
		size_t size;

		size = kmsg->memfds_count * sizeof(int);
		queue->memfds = kmalloc(size, GFP_KERNEL);
		if (!queue->memfds)
			return -ENOMEM;

		size = kmsg->memfds_count * sizeof(struct file *);
		queue->memfds_fp = kzalloc(size, GFP_KERNEL);
		if (!queue->memfds_fp)
			return -ENOMEM;
	}

	KDBUS_ITEM_FOREACH(item, &kmsg->msg) {
		switch (item->type) {
		case KDBUS_MSG_PAYLOAD_VEC: {
			/* Add item, and copy data from the sender into the
			 * receiver's pool. */
			size_t size = KDBUS_ITEM_HEADER_SIZE +
				      sizeof(struct kdbus_vec);
			char tmp[size];
			struct kdbus_item *it = (struct kdbus_item *)tmp;

			it->type = KDBUS_MSG_PAYLOAD_VEC;
			it->size = size;

			/* A NULL address is a "padding vec" for alignement */
			if (KDBUS_VEC_PTR(&item->vec))
				it->vec.address = KDBUS_VEC_ADDR(vec_data);
			else
				it->vec.address = KDBUS_VEC_ADDR(NULL);
			it->vec.size = item->vec.size;
			if (copy_to_user(items, it, size))
				return -EFAULT;

			ret = kdbus_pool_map_write(&pool_map,
						   KDBUS_VEC_PTR(&item->vec),
						   item->vec.size);
			if (ret < 0)
				return ret;

			items = KDBUS_ITEM_NEXT(items);
			vec_data += item->vec.size;
			break;
		}

		case KDBUS_MSG_PAYLOAD_MEMFD: {
			/* Add item, grab reference of passed-in PAYLOAD_FD,
			 * remember the location of the fd number which will
			 * be updated at RECV time */
			size_t size = KDBUS_ITEM_HEADER_SIZE +
				      sizeof(struct kdbus_memfd);
			char tmp[size];
			struct kdbus_item *it = (struct kdbus_item *)tmp;
			struct file *fp;

			it->type = KDBUS_MSG_PAYLOAD_MEMFD;
			it->size = size;
			it->memfd.size = item->memfd.size;
			it->memfd.fd = -1;
			if (copy_to_user(items, it, size))
				return -EFAULT;

			ret = kdbus_conn_memfd_ref(item, &fp);
			if (ret < 0)
				return ret;

			queue->memfds[queue->memfds_count] = &items->memfd.fd;
			queue->memfds_fp[queue->memfds_count] = fp;
			queue->memfds_count++;
			items = KDBUS_ITEM_NEXT(items);
			break;
		}

		default:
			break;
		}
	}

	if (kmsg->vecs_count > 0)
		kdbus_pool_map_close(&pool_map);

	return 0;
}

void kdbus_conn_queue_cleanup(struct kdbus_conn_queue *queue)
{
	kdbus_conn_memfds_unref(queue);
	kdbus_conn_fds_unref(queue);
	kfree(queue);
}

/* enqueue a message into the receiver's connection */
int kdbus_conn_queue_insert(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg,
			    u64 deadline_ns)
{
	struct kdbus_conn_queue *queue;
	void __user *buf;
	u64 msg_size;
	size_t payloads = 0;
	size_t fds = 0;
	size_t meta = 0;
	size_t vec_data;
	int ret = 0;

	if (!conn->active)
		return -ENOTCONN;

	if (kmsg->fds && !(conn->flags & KDBUS_HELLO_ACCEPT_FD))
		return -ECOMM;

	queue = kzalloc(sizeof(struct kdbus_conn_queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	INIT_LIST_HEAD(&queue->entry);

	/* copy message properies we need for the queue management */
	queue->deadline_ns = deadline_ns;
	queue->src_id = kmsg->msg.src_id;
	queue->cookie = kmsg->msg.cookie;
	if (kmsg->msg.flags & KDBUS_MSG_FLAGS_EXPECT_REPLY)
		queue->expect_reply = true;

	/* space for message header */
	msg_size = KDBUS_MSG_HEADER_SIZE;

	/* space for PAYLOAD items */
	if (kmsg->vecs_count + kmsg->memfds_count > 0) {
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
	if (kmsg->meta_size > 0) {
		meta = msg_size;
		msg_size += kmsg->meta_size;
	}

	/* data starts after the message */
	vec_data = KDBUS_ALIGN8(msg_size);

	/* allocate the needed space in the pool of the receiver */
	mutex_lock(&conn->lock);
	if (conn->msg_count > KDBUS_CONN_MAX_MSGS) {
		ret = -EXFULL;
		goto exit_unlock;
	}

	buf = kdbus_pool_alloc(&conn->pool, vec_data + kmsg->vecs_size);
	if (!buf) {
		ret = -EXFULL;
		goto exit_unlock;
	}
	mutex_unlock(&conn->lock);

	/* update and copy the message header */
	if (copy_to_user(buf, &kmsg->msg, KDBUS_MSG_HEADER_SIZE)) {
		ret = -EFAULT;
		goto exit;
	}

	/* update the size */
	if (kdbus_size_set_user(msg_size, buf, struct kdbus_msg)) {
		ret = -EFAULT;
		goto exit;
	}

	/* add PAYLOAD items */
	if (kmsg->vecs_count + kmsg->memfds_count > 0) {
		ret = kdbus_conn_payload_add(queue, kmsg, conn->task,
					     buf + payloads, buf + vec_data);
		if (ret < 0)
			goto exit;
	}

	/* add a FDS item; the array content will be updated at RECV time */
	if (kmsg->fds_count > 0) {
		size_t size = KDBUS_ITEM_HEADER_SIZE;
		char tmp[size];
		struct kdbus_item *it = (struct kdbus_item *)tmp;

		it->type = KDBUS_MSG_FDS;
		it->size = size + (kmsg->fds_count * sizeof(int));
		if (copy_to_user(buf + fds, it, size)) {
			ret = -EFAULT;
			goto exit;
		}

		ret = kdbus_conn_fds_ref(queue, kmsg->fds, kmsg->fds_count);
		if (ret < 0)
			goto exit;

		/* remember the array to update at RECV */
		queue->fds = buf + fds + KDBUS_ITEM_HEADER_SIZE;
		queue->fds_count = kmsg->fds_count;
	}

	/* append message metadata/credential items */
	if (kmsg->meta_size > 0) {
		if (copy_to_user(buf + meta, kmsg->meta, kmsg->meta_size)) {
			ret = -EFAULT;
			goto exit;
		}
	}

	/* remember the pointer to the message */
	queue->msg = buf;

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
	return ret;
}

static int kdbus_conn_fds_install(struct kdbus_conn_queue *queue)
{
	size_t size;
	unsigned int i;
	int *fds;
	int ret = 0;

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
	if (copy_to_user(queue->fds, fds, size)) {
		ret = -EFAULT;
		goto remove_unused;
	}

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

static int kdbus_conn_memfds_install(struct kdbus_conn_queue *queue, int **memfds)
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
		if (put_user(fds[i], queue->memfds[i])) {
			ret = -EFAULT;
			goto remove_unused;
		}
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
kdbus_conn_recv_msg(struct kdbus_conn *conn, struct kdbus_msg __user **msg_ptr)
{
	struct kdbus_conn_queue *queue;
	int *memfds = NULL;
	unsigned int i;
	int ret;

	if (!KDBUS_IS_ALIGNED8((unsigned long)msg_ptr))
		return -EFAULT;

	mutex_lock(&conn->lock);
	if (conn->msg_count == 0) {
		ret = -EAGAIN;
		goto exit_unlock;
	}

	/* return the address of the next message in the pool */
	queue = list_first_entry(&conn->msg_list,
				 struct kdbus_conn_queue, entry);
	if (put_user(queue->msg, msg_ptr)) {
		ret = -EFAULT;
		goto exit_unlock;
	}

	/* Install KDBUS_MSG_PAYLOAD_MEMFDs file descriptors, we return
	 * the list of file descriptors to be able to cleanup on error. */
	if (queue->memfds_count) {
		ret = kdbus_conn_memfds_install(queue, &memfds);
		if (ret < 0)
			goto exit_unlock;
	}

	/* install KDBUS_MSG_FDS file descriptors */
	if (queue->fds_count) {
		ret = kdbus_conn_fds_install(queue);
		if (ret < 0)
			goto exit_rewind;
	}

	kfree(memfds);

	conn->msg_count--;
	list_del(&queue->entry);
	mutex_unlock(&conn->lock);

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
			kdbus_pool_free(&conn->pool, queue->msg);
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

void kdbus_conn_timeout_schedule_scan(struct kdbus_conn *conn)
{
	schedule_work(&conn->work);
}

static void kdbus_conn_timer_func(unsigned long val)
{
	struct kdbus_conn *conn = (struct kdbus_conn *) val;
	kdbus_conn_timeout_schedule_scan(conn);
}

#ifdef CONFIG_AUDITSYSCALL
static void kdbus_conn_set_audit(struct kdbus_conn *conn)
{
	const struct cred *cred;
	uid_t uid;

	rcu_read_lock();
	cred = __task_cred(current);
	uid = from_kuid(cred->user_ns, audit_get_loginuid(current));
	rcu_read_unlock();

	conn->audit_ids[0] = uid;
	conn->audit_ids[1] = audit_get_sessionid(current);
}
#else
static inline void kdbus_conn_set_audit(struct kdbus_conn *conn) {}
#endif

#ifdef CONFIG_SECURITY
static void kdbus_conn_set_seclabel(struct kdbus_conn *conn)
{
	u32 sid;

	security_task_getsecid(current, &sid);
	security_secid_to_secctx(sid, &conn->sec_label, &conn->sec_label_len);
}
#else
static inline void kdbus_conn_set_seclabel(struct kdbus_conn *conn) {}
#endif

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
		pr_debug("opened control device '%s/control'\n",
			 conn->ns->devpath);
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

	/* get and register new id for this connection */
	conn->id = conn->ep->bus->conn_id_next++;

	/* add this connection to hash table */
	hash_add(conn->ep->bus->conn_hash, &conn->hentry, conn->id);

	mutex_init(&conn->lock);
	mutex_init(&conn->names_lock);
	mutex_init(&conn->accounting_lock);
	INIT_LIST_HEAD(&conn->msg_list);
	INIT_LIST_HEAD(&conn->names_list);
	INIT_LIST_HEAD(&conn->names_queue_list);
	INIT_LIST_HEAD(&conn->connection_entry);

	list_add_tail(&conn->connection_entry, &conn->ep->connection_list);

	file->private_data = conn;
	mutex_unlock(&conn->ns->lock);

	INIT_WORK(&conn->work, kdbus_conn_work);

	init_timer(&conn->timer);
	conn->timer.expires = 0;
	conn->timer.function = kdbus_conn_timer_func;
	conn->timer.data = (unsigned long) conn;
	add_timer(&conn->timer);

	conn->match_db = kdbus_match_db_new();

	conn->creds.uid = from_kuid_munged(current_user_ns(), current_uid());
	conn->creds.gid = from_kgid_munged(current_user_ns(), current_gid());
	conn->creds.pid = current->pid;
	conn->creds.tid = current->tgid;
	conn->creds.starttime = timespec_to_ns(&current->start_time);

	kdbus_conn_set_audit(conn);
	kdbus_conn_set_seclabel(conn);

	pr_debug("created endpoint bus connection %llu '%s/%s'\n",
		 (unsigned long long)conn->id, conn->ns->devpath,
		 conn->ep->bus->name);

	//FIXME: cleanup here!
	ret = kdbus_notify_id_change(conn->ep, KDBUS_MSG_ID_ADD, conn->id, conn->flags);
	if (ret < 0)
		return ret;

	/* pin and store the task, so a sender can copy to the receiver */
	get_task_struct(current);
	conn->task = current;
	return 0;

exit_unlock:
	mutex_unlock(&conn->ns->lock);
	kfree(conn);
	return ret;
}

static int kdbus_conn_release(struct inode *inode, struct file *file)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_bus *bus;

	switch (conn->type) {
	case KDBUS_CONN_NS_OWNER:
		break;

	case KDBUS_CONN_BUS_OWNER:
		kdbus_bus_disconnect(conn->bus_owner);
		kdbus_bus_unref(conn->bus_owner);
		break;

	case KDBUS_CONN_EP: {
		struct kdbus_conn_queue *queue, *tmp;
		struct list_head list;

		INIT_LIST_HEAD(&list);

		hash_del(&conn->hentry);
		list_del(&conn->connection_entry);

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
				kdbus_pool_free(&conn->pool, queue->msg);
				kdbus_conn_queue_cleanup(queue);
			}
		}
		mutex_unlock(&conn->lock);

		list_for_each_entry_safe(queue, tmp, &list, entry) {
			kdbus_notify_reply_dead(conn->ep, queue->src_id,
						queue->cookie);
			mutex_lock(&conn->lock);
			kdbus_pool_free(&conn->pool, queue->msg);
			mutex_unlock(&conn->lock);
			kdbus_conn_queue_cleanup(queue);
			list_del(&queue->entry);
		}

		del_timer(&conn->timer);
		cancel_work_sync(&conn->work);

#ifdef CONFIG_SECURITY
		kfree(conn->sec_label);
#endif

		bus = conn->ep->bus;
		kdbus_name_remove_by_conn(bus->name_registry, conn);
		if (conn->ep->policy_db)
			kdbus_policy_db_remove_conn(conn->ep->policy_db, conn);
		kdbus_match_db_unref(conn->match_db);
		kdbus_ep_unref(conn->ep);

		put_task_struct(current);
		break;
	}

	default:
		break;
	}

	kdbus_ns_unref(conn->ns);
	kfree(conn);
	return 0;
}

static bool check_flags(u64 kernel_flags)
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
		gid_t gid = 0;

		ret = kdbus_bus_make_user(buf, &bus_kmake);
		if (ret < 0)
			break;

		if (!check_flags(bus_kmake->make.flags)) {
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
		conn->type = KDBUS_CONN_BUS_OWNER;
		conn->bus_owner = bus;
		break;
	}

	case KDBUS_CMD_NS_MAKE:
		ret = kdbus_ns_kmake_user(buf, &ns_kmake);
		if (ret < 0)
			break;

		if (!check_flags(ns_kmake->make.flags))
			return -ENOTSUPP;

		if (ns_kmake->make.flags & KDBUS_MAKE_ACCESS_WORLD)
			mode = 0666;

		ret = kdbus_ns_new(kdbus_ns_init, ns_kmake->name, mode, &ns);
		if (ret < 0)
			return ret;

		/* turn the control fd into a new ns owner device */
		conn->type = KDBUS_CONN_NS_OWNER;
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

/* kdbus bus endpoint commands */
static long kdbus_conn_ioctl_ep(struct file *file, unsigned int cmd,
				void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_ep_kmake *kmake = NULL;
	struct kdbus_cmd_hello *hello = NULL;
	struct kdbus_bus *bus = NULL;
	long ret = 0;

	if (conn && conn->ep)
		bus = conn->ep->bus;

	switch (cmd) {
	case KDBUS_CMD_EP_MAKE: {
		umode_t mode = 0;
		gid_t gid = 0;

		ret = kdbus_ep_kmake_user(buf, &kmake);
		if (ret < 0)
			break;

		if (!check_flags(kmake->make.flags)) {
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

		break;
	}

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
		const struct kdbus_item *item;
		size_t size;
		void *v;

		if (conn->active) {
			ret = -EISCONN;
			break;
		}

		if (kdbus_size_get_user(size, buf, struct kdbus_cmd_hello)) {
			ret = -EFAULT;
			break;
		}

		if (size < sizeof(struct kdbus_cmd_hello) || size > KDBUS_HELLO_MAX_SIZE) {
			ret = -EMSGSIZE;
			break;
		}

		v = memdup_user(buf, size);
		if (IS_ERR(v)) {
			ret = PTR_ERR(v);
			break;
		}
		hello = v;

		if (!check_flags(hello->conn_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		KDBUS_ITEM_FOREACH_VALIDATE(item, hello) {
			/* empty items are invalid */
			if (item->size <= KDBUS_ITEM_HEADER_SIZE) {
				ret = -EINVAL;
				break;
			}

			switch (item->type) {
			case KDBUS_HELLO_POOL:
				if (!KDBUS_VEC_PTR(&item->vec) ||
				    item->vec.size == 0) {
					ret = -EINVAL;
					break;
				}

				/* enforce page alignment and page granularity */
				if (!KDBUS_IS_ALIGNED_PAGE(item->vec.address) ||
				    !KDBUS_IS_ALIGNED_PAGE(item->vec.size)) {
					ret = -EFAULT;
					break;
				}

				conn->pool.buf = KDBUS_VEC_PTR(&item->vec);
				conn->pool.size = item->vec.size;
				break;

			default:
				ret = -ENOTSUPP;
			}
		}

		/* return properties of this connection to the caller */
		hello->bus_flags = bus->bus_flags;
		hello->bloom_size = bus->bloom_size;
		hello->id = conn->id;
		if (copy_to_user(buf, hello, sizeof(struct kdbus_cmd_hello))) {
			ret = -EFAULT;
			break;
		}

		conn->flags = hello->conn_flags;
		conn->active = true;

		break;
	}

	case KDBUS_CMD_EP_POLICY_SET:
		/* upload a policy for this endpoint */
		if (!conn->ep->policy_db)
			conn->ep->policy_db = kdbus_policy_db_new();
		if (!conn->ep->policy_db)
			return -ENOMEM;

		ret = kdbus_cmd_policy_set_from_user(conn->ep->policy_db, buf);
		break;

	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */
		ret = kdbus_cmd_name_acquire(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */
		ret = kdbus_cmd_name_release(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_NAME_LIST:
		/* return all current well-known names */
		ret = kdbus_cmd_name_list(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_NAME_QUERY:
		/* return details about a specific well-known name */
		ret = kdbus_cmd_name_query(bus->name_registry, conn, buf);
		break;

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */
		ret = kdbus_cmd_match_db_add(conn, buf);
		break;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */
		ret = kdbus_cmd_match_db_remove(conn->match_db, buf);
		break;

	case KDBUS_CMD_MONITOR: {
		/* turn on/turn off monitor mode */
		struct kdbus_cmd_monitor cmd_monitor;
		if (copy_from_user(&cmd_monitor, buf, sizeof(cmd_monitor)))
			return -EFAULT;

		conn->monitor = !!cmd_monitor.enabled;
		break;
	}

	case KDBUS_CMD_MSG_SEND: {
		struct kdbus_kmsg *kmsg;

		/* submit a message which will be queued in the receiver */
		ret = kdbus_kmsg_new_from_user(conn, buf, &kmsg);
		if (ret < 0)
			break;

		ret = kdbus_kmsg_send(conn->ep, conn, kmsg);
		kdbus_kmsg_free(kmsg);
		break;
	}

	case KDBUS_CMD_MSG_RECV:
		/* receive a pointer to a queued message */
		ret = kdbus_conn_recv_msg(conn, buf);
		break;

	case KDBUS_CMD_MSG_RELEASE: {
		/* cleanup the memory used in the receiver's pool */
		mutex_lock(&conn->lock);
		kdbus_pool_free(&conn->pool, buf);
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

	kfree(kmake);
	kfree(hello);

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
	if (conn->type != KDBUS_CONN_EP)
		return POLLERR | POLLHUP;

	poll_wait(file, &conn->ep->wait, wait);

	mutex_lock(&conn->lock);
	if (!list_empty(&conn->msg_list))
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&conn->lock);

	return mask;
}

const struct file_operations kdbus_device_ops = {
	.owner =		THIS_MODULE,
	.open =			kdbus_conn_open,
	.release =		kdbus_conn_release,
	.poll =			kdbus_conn_poll,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	kdbus_conn_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		kdbus_conn_ioctl,
#endif
};
