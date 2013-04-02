/*
 * portal
 *	Test code for dealing with shoving data around different character
 *	devices.  I want a framework to see how well the kmsg-as-a-kref idea
 *	works out.
 *
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>

/* userspace api */
#include "portal.h"

struct kmsg {
	struct kref	kref;
	u32		dst_id;
	u32		src_id;
	u32		size;
	u32		msg_id;
	char		data[0];
};

struct kmsg_list_entry {
	struct kmsg		*kmsg;
	struct list_head	entry;
};

/* 4 connections for testing */
static struct connection {
	int			id;
	struct list_head	msg_list;
	struct mutex		msg_lock;
	wait_queue_head_t	wait;		/* wake up this connection */
} conn1, conn2, conn3, conn4;

static u32 msg_id_next;

static void init_connection(struct connection *conn, int id)
{
	conn->id = id;
	mutex_init(&conn->msg_lock);
	INIT_LIST_HEAD(&conn->msg_list);
	init_waitqueue_head(&conn->wait);
}


static struct class portal_class = {
	.name = "portal",
};

/* List of all connections in the system. */
/* Well, really only the endpoint connections,
 * that's all we care about for now */
static LIST_HEAD(connection_list);

static struct connection *minor_to_conn(int minor)
{
	/* Aren't static variables grand? */
	if (minor == 0)
		return &conn1;
	if (minor == 1)
		return &conn2;
	if (minor == 2)
		return &conn3;
	if (minor == 3)
		return &conn4;
	return NULL;
}

static void msg_release(struct kref *kref)
{
	struct kmsg *msg = container_of(kref, struct kmsg, kref);

	pr_info("%s: freeing message %p, msg_id = %d, dst_id = %d, src_id = %d, size = %d",
		__func__, msg,
		msg->msg_id, msg->dst_id, msg->src_id, msg->size);
	kfree(msg);
}

static int msg_new(struct connection *conn, struct umsg __user *umsg,
		   struct kmsg **kmsg)
{
	struct kmsg *m;
	u32 size;
	int ret;

	if (copy_from_user(&size, &umsg->size, sizeof(size)))
		return -EFAULT;

	if (size > PAGE_SIZE)
		return -ENOMEM;

	m = kzalloc(sizeof(struct kmsg) + size, GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	if (copy_from_user(m->data, umsg->data, size)) {
		ret = -EFAULT;
		goto out_ret;
	}

	if (copy_from_user(&m->dst_id, &umsg->dst_id, sizeof(u32))) {
		kfree(m);
		return -EFAULT;
	}

	kref_init(&m->kref);
	m->src_id = conn->id;
	m->size = size;
	m->msg_id = msg_id_next++;
	*kmsg = m;
	return 0;
out_ret:
	kfree(m);
	return ret;
}

static int msg_send(struct connection *conn, struct kmsg *msg)
{
	struct kmsg_list_entry *msg_list_entry;
	struct connection *conn_dst;

	conn_dst = minor_to_conn(msg->dst_id-1);
	if (!conn_dst)
		return -ENOENT;

	pr_info("sending message %d from %d to %d\n",
		msg->msg_id, msg->src_id, msg->dst_id);

	/* Create a new msg list entry, attach our message to it, and fire it off */
	msg_list_entry = kmalloc(sizeof(*msg_list_entry), GFP_KERNEL);
	kref_get(&msg->kref);
	msg_list_entry->kmsg = msg;

	mutex_lock(&conn_dst->msg_lock);
	list_add_tail(&msg_list_entry->entry, &conn_dst->msg_list);
	mutex_unlock(&conn_dst->msg_lock);

	/* wake up the other processes.  Hopefully... */
	wake_up_interruptible_all(&conn_dst->wait);

	/* drop our reference on the message, as we are done with it */
	kref_put(&msg->kref, msg_release);
	return 0;
}

static int msg_recv(struct connection *conn, struct umsg __user *umsg)
{
	struct kmsg_list_entry *msg_entry, *tmp_entry;
	struct kmsg *msg;
	int msg_size;
	ssize_t retval = -ENODATA;
	u32 user_size;

	pr_info("receiving message for %d\n", conn->id);

	if (copy_from_user(&user_size, &umsg->size, sizeof(user_size)))
		return -EFAULT;

	if (user_size > PAGE_SIZE)
		return -ENOMEM;

	if (mutex_lock_interruptible(&conn->msg_lock))
		return -ERESTARTSYS;

	if (list_empty(&conn->msg_list))
		goto exit;

	/* let's grab a message from our list to write out */
	list_for_each_entry_safe(msg_entry, tmp_entry, &conn->msg_list, entry) {
		msg = msg_entry->kmsg;
		msg_size = msg->size;
		if (msg_size > user_size) {
			retval = -EMSGSIZE;
			goto exit;
		}

		if (copy_to_user(&umsg->data[0], &msg->data[0], msg_size)) {
			retval = -EFAULT;
			goto exit;
		}
		if (copy_to_user(&umsg->dst_id, &msg->dst_id, sizeof(umsg->dst_id))) {
			retval = -EFAULT;
			goto exit;
		}
		if (copy_to_user(&umsg->size, &msg->size, sizeof(umsg->size))) {
			retval = -EFAULT;
			goto exit;
		}
		list_del(&msg_entry->entry);
		kfree(msg_entry);
		kref_put(&msg->kref, msg_release);
		retval = 0;
		break;
	}

exit:
	mutex_unlock(&conn->msg_lock);
	return retval;
}

static int conn_open(struct inode *inode, struct file *file)
{
	struct connection *conn;
	int minor;

	minor = MINOR(inode->i_rdev);
	conn = minor_to_conn(minor);
	if (!conn) {
		pr_err("minor '%d' isn't valid?\n", minor);
		return -EINVAL;
	}

	file->private_data = conn;

	pr_info("connection %d opened\n", conn->id);

	return 0;
}

static int conn_release(struct inode *inode, struct file *file)
{
	struct connection *conn = file->private_data;
	struct kmsg *msg;
	struct kmsg_list_entry *msg_entry, *tmp_entry;

	/* Wake up anything sleeping */
//	wake_up_interruptible_all(&conn->wait);

	/* clean up any messages still left on this endpoint */
	if (mutex_lock_interruptible(&conn->msg_lock))
		return -ERESTARTSYS;

	list_for_each_entry_safe(msg_entry, tmp_entry, &conn->msg_list, entry) {
		msg = msg_entry->kmsg;
		list_del(&msg_entry->entry);
		kfree(msg_entry);
		kref_put(&msg->kref, msg_release);
	}
	mutex_unlock(&conn->msg_lock);

	pr_info("connection %d closed\n", conn->id);
	return 0;
}

static long conn_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct connection *conn = file->private_data;
	struct kmsg *msg;
	int ret;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case PORTAL_MSG_SEND:
		pr_info("connection %d: send message\n", conn->id);
		ret = msg_new(conn, argp, &msg);
		if (ret < 0)
			return ret;
		return msg_send(conn, msg);

	case PORTAL_MSG_RECV:
		pr_info("connection %d: receive message\n", conn->id);
		return msg_recv(conn, argp);
	}

	pr_info("%s: bad command, %d\n", __func__, cmd);
	return -EINVAL;
}

static unsigned int conn_poll(struct file *file, struct poll_table_struct *wait)
{
	struct connection *conn = file->private_data;
	unsigned int mask = 0;

	poll_wait(file, &conn->wait, wait);

	mutex_lock(&conn->msg_lock);
	if (!list_empty(&conn->msg_list))
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&conn->msg_lock);

	return 0;
}

static int conn_mmap(struct file *file, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static ssize_t conn_write(struct file *file, const char __user *ubuf,
			  size_t count, loff_t *ppos)
{
	pr_info("%s: use the ioctl instead\n", __func__);
	return -EINVAL;

}

static ssize_t conn_read(struct file *file, char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	struct connection *conn = file->private_data;
	struct kmsg_list_entry *msg_entry, *tmp_entry;
	struct kmsg *msg;
	int msg_size;
	ssize_t retval = 0;

	pr_info("connection %d reading\n", conn->id);

	if (count == 0)
		return 0;

	if (mutex_lock_interruptible(&conn->msg_lock))
		return -ERESTARTSYS;

	if (list_empty(&conn->msg_list))
		goto exit;

	/* let's grab a message from our list to write out */
	list_for_each_entry_safe(msg_entry, tmp_entry, &conn->msg_list, entry) {
		msg = msg_entry->kmsg;
		msg_size = msg->size;
		if (msg_size > count) {
			retval = -EMSGSIZE;
			goto exit;
		}

		if (copy_to_user(ubuf, &msg->data[0], msg_size)) {
			retval = -EFAULT;
			goto exit;
		}
		list_del(&msg_entry->entry);
		kfree(msg_entry);
		retval = msg_size;
		kref_put(&msg->kref, msg_release);
		break;
	}

exit:
	mutex_unlock(&conn->msg_lock);
	return retval;
}

static const struct file_operations portal_device_ops = {
	.owner =		THIS_MODULE,
	.open =			conn_open,
	.release =		conn_release,
	.unlocked_ioctl =	conn_ioctl,
	.compat_ioctl =		conn_ioctl,
	.poll =			conn_poll,
	.mmap =			conn_mmap,
	.llseek =		noop_llseek,
	.write =		conn_write,
	.read =			conn_read,
};

static int portal_major;	/* Our major number */

static int __init portal_init(void)
{
	int ret;
	struct device *dev;

	ret = class_register(&portal_class);
	if (ret < 0)
		return ret;

	init_connection(&conn1, 1);
	init_connection(&conn2, 2);
	init_connection(&conn3, 3);
	init_connection(&conn4, 4);

	/* Create our static device nodes, with one dynamic major */
	portal_major = register_chrdev(0, "portal", &portal_device_ops);
	if (portal_major < 0) {
		ret = portal_major;
		goto ret;
	}

	/* Create 4 sysfs entries */
	dev = device_create(&portal_class, NULL, MKDEV(portal_major, 0), NULL, "portal1");
	dev = device_create(&portal_class, NULL, MKDEV(portal_major, 1), NULL, "portal2");
	dev = device_create(&portal_class, NULL, MKDEV(portal_major, 2), NULL, "portal3");
	dev = device_create(&portal_class, NULL, MKDEV(portal_major, 3), NULL, "portal4");

	pr_info("initialized\n");
	return 0;
ret:
	class_unregister(&portal_class);
	return ret;
}

static void __exit portal_exit(void)
{
	device_destroy(&portal_class, MKDEV(portal_major, 0));
	device_destroy(&portal_class, MKDEV(portal_major, 1));
	device_destroy(&portal_class, MKDEV(portal_major, 2));
	device_destroy(&portal_class, MKDEV(portal_major, 3));
	class_unregister(&portal_class);
	unregister_chrdev(portal_major, "portal");
	pr_info("unloaded\n");
}

module_init(portal_init);
module_exit(portal_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("portal subether manipulator tester");
