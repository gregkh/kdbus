/*
 * portal - test code for dealing with shoving data around different character devices
 *
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
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

/* Public stuff */
struct umsg {
	__u32	dst_id;
	__u32	size;
	char	data[0];
};

#define PORTAL_IOC_MAGIC 0x96

enum portal_cmd {
	PORTAL_MSG_SEND =	_IOWR(PORTAL_IOC_MAGIC, 0x80, struct umsg),
	PORTAL_MSG_RECV =	_IOWR(PORTAL_IOC_MAGIC, 0x81, struct umsg),
};

/* End public stuff */

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
} conn1, conn2, conn3, conn4;

static u32 msg_id_next;

static void init_connection(struct connection *conn, int id)
{
	conn->id = id;
	mutex_init(&conn->msg_lock);
	INIT_LIST_HEAD(&conn->msg_list);
}


static struct bus_type portal_subsys = {
	.name = "portal",
};

/* List of all connections in the system. */
/* Well, really only the endpoint connections,
 * that's all we care about for now */
static LIST_HEAD(connection_list);

static int msg_new(struct connection *conn, struct umsg __user *umsg, struct kmsg **kmsg);
static int msg_send(struct connection *conn, struct kmsg *msg);


static void msg_release(struct kref *kref)
{
	struct kmsg *msg = container_of(kref, struct kmsg, kref);
	kfree(msg);
}

struct connection *minor_to_conn(int minor)
{
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

	/* clean up any messages still left on this endpoint */
	mutex_lock(&conn->msg_lock);
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
	int err;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case PORTAL_MSG_SEND:
		pr_info("connection %d: send message\n", conn->id);
		err = msg_new(conn, argp, &msg);
		if (err < 0)
			return err;
		return msg_send(conn, msg);

	case PORTAL_MSG_RECV:
		pr_info("connection %d: receive message\n", conn->id);
		pr_info("Use the read syscall instead to get the data\n");
		return -ENOSYS;
	}

	pr_info("%s: bad command, %d\n", __func__, cmd);
	return -EINVAL;
}

static unsigned int kdbus_conn_poll(struct file *file,
				    struct poll_table_struct *wait)
{
	struct kdbus_conn *conn = file->private_data;
	unsigned int mask = 0;

	poll_wait(file, &conn->ep->wait, wait);

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

static ssize_t kdbus_conn_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_conn *temp_conn;
	struct kdbus_test_msg *msg;

	pr_info("%s: \n");
	/* FIXME: Let's cap a message size at PAGE_SIZE for now */
	if (count > PAGE_SIZE)
		return -EINVAL;

	if (count == 0)
		return 0;

	msg = kmalloc((sizeof(*msg) + count), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	if (copy_from_user(&msg->data[0], ubuf, count))
		return -EFAULT;

	kref_init(&msg->kref);
	msg->length = count;

	/* Walk the list of connections,
	 * find any endpoints that match our endpoint,
	 * create a kdbus_msg_list_entry for it,
	 * attach the message to the endpoint list,
	 * wake the connection up. */

	/* what do we lock here?  FIXME */

	list_for_each_entry(temp_conn, &connection_list, connection_entry) {
		if (temp_conn->type != KDBUS_CONN_EP)
			continue;
		if (temp_conn->ep == conn->ep) {
			/* Matching endpoints */
			struct kdbus_msg_list_entry *msg_list_entry;

			msg_list_entry = kmalloc(sizeof(*msg_list_entry), GFP_KERNEL);
			kref_get(&msg->kref);
			msg_list_entry->msg = msg;
			mutex_lock(&temp_conn->msg_lock);
			list_add_tail(&temp_conn->msg_list, &msg_list_entry->entry);
			mutex_unlock(&temp_conn->msg_lock);
			/* wake up the other processes.  Hopefully... */
			wake_up_interruptible_all(&temp_conn->ep->wait);
		}
	}

	/* drop our reference on the message, as we are done with it */
	kref_put(&msg->kref, msg_release);
	return count;
}

static ssize_t kdbus_conn_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_msg_list_entry *msg_list_entry;
	struct kdbus_test_msg *msg;
	ssize_t retval = 0;

	/* Only an endpoint can read/write data */
	if (conn->type != KDBUS_CONN_EP)
		return -EINVAL;

	if (count == 0)
		return 0;

	if (mutex_lock_interruptible(&conn->msg_lock))
		return -ERESTARTSYS;

	while (list_empty(&conn->msg_list)) {
		/* Nothing to read, so try again or sleep */
		mutex_unlock(&conn->msg_lock);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		/* sleep until we get something */
		if (wait_event_interruptible(conn->ep->wait, list_empty(&conn->msg_list)))
			return -ERESTARTSYS;

		if (mutex_lock_interruptible(&conn->msg_lock))
			return -ERESTARTSYS;
	}

	/* let's grab a message from our list to write out */
	if (!list_empty(&conn->msg_list)) {
		msg_list_entry = list_entry(&conn->msg_list, struct kdbus_msg_list_entry, entry);
		msg = msg_list_entry->msg;
		if (msg->length > count) {
			retval = -E2BIG;		// FIXME wrong error code, I know, what should we use?
			goto exit;
		}
		if (copy_to_user(ubuf, &msg->data[0], msg->length)) {
			retval = -EFAULT;
			goto exit;
		}
		list_del(&msg_list_entry->entry);
		kfree(msg_list_entry);
		retval = msg->length;
		kref_put(&msg->kref, msg_release);
	}

exit:
	mutex_unlock(&conn->msg_lock);
	return retval;
}

const struct file_operations kdbus_device_ops = {
	.owner =		THIS_MODULE,
	.open =			conn_open,
	.release =		conn_release,
	.unlocked_ioctl =	conn_ioctl,
	.compat_ioctl =		conn_ioctl,
	.poll = 		kdbus_conn_poll,
	.mmap =			conn_mmap,
	.llseek =		noop_llseek,
	.write = 		kdbus_conn_write,
	.read =			kdbus_conn_read,
};


static int msg_new(struct connection *conn, struct umsg __user *umsg, struct kmsg **kmsg)
{
	struct kmsg *m;
	int err;

	if (umsg->size > PAGE_SIZE)
		return -ENOMEM;

	m = kzalloc(sizeof(struct kmsg) + umsg->size, GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	if (copy_from_user(m->data, umsg->data, umsg->size)) {
		err = -EFAULT;
		goto out_err;
	}

	kref_init(&m->kref);
	m->dst_id = umsg->dst_id;
	m->src_id = conn->id;
	m->msg_id = msg_id_next++;
	*kmsg = m;
	return 0;
out_err:
	kfree(m);
	return err;
}

static int msg_send(struct connection *conn, struct kmsg *msg)
{
	struct connection *conn_dst;

	conn_dst = minor_to_conn(msg->dst_id-1);
	if (!conn_dst)
		return -ENOENT;

	// FIXME

	pr_info("sending message %llu from %llu to %llu\n",
		(unsigned long long)msg->msg_id,
		(unsigned long long)msg->src_id,
		(unsigned long long)msg->dst_id);

	kfree(msg);
	return 0;
}

static int __init portal_init(void)
{
	int err;

	err = bus_register(&portal_subsys);
	if (err < 0)
		return err;

	init_connection(&conn1, 1);
	init_connection(&conn2, 2);
	init_connection(&conn3, 3);
	init_connection(&conn4, 4);

	pr_info("initialized\n");
	return 0;
}

static void __exit portal_exit(void)
{
	bus_unregister(&portal_subsys);
	pr_info("unloaded\n");
}

module_init(portal_init);
module_exit(portal_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("portal manipulator");
