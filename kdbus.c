/*
 * kdbus - interprocess message routing
 *
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
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
//#include <uapi/linux/major.h>
#include "kdbus.h"

#include "kdbus_internal.h"

/*
 * TODO:
 * - set parent for driver-core /sys/devices/kdbus!... devices to virtual/kdbus/,
 *   the bus subsys misses the "no parent" logic the class subsys has
 *
 * - switch to a 64bit idr for connection id <--> kdbus_conn
 *
 * - convert Greg's 8 pages of notes into workable code...
 */

/*
 * Example of device nodes in /dev. For any future changes, keep in mind,
 * that the layout should support a possible /dev/kdbus/ filesystem for the
 * init namspace and one for each sub-namespace.
 *
 * /dev/kdbus/
 * |-- control
 * |-- system
 * |   |-- bus
 * |   |-- ep-epiphany
 * |   `-- ep-firefox
 * |-- 2702-user
 * |   `-- bus
 * |-- 1000-user
 * |   `-- bus
 * `-- ns
 *     |-- myfedoracontainer
 *     |   |-- control
 *     |   |-- system
 *     |   |   `-- bus
 *     |   `-- 1000-user
 *     |       `-- bus
 *     `-- mydebiancontainer
 *         |-- control
 *         |-- system
 *             `-- bus
 */

/* kdbus sysfs subsystem */
struct bus_type kdbus_subsys = {
	.name = "kdbus",
};

/* List of all connections in the system. */
/* Well, really only the endpoint connections,
 * that's all we care about for now */
static LIST_HEAD(connection_list);

/* kdbus initial namespace */
static struct kdbus_ns *kdbus_ns_init;

/* map of majors to namespaces */
DEFINE_IDR(kdbus_ns_major_idr);

/* namespace list lock */
DEFINE_MUTEX(kdbus_subsys_lock);

static int kdbus_msg_new(struct kdbus_conn *conn, struct kdbus_msg __user *umsg,
			 struct kdbus_msg **msg);
static int kdbus_msg_send(struct kdbus_conn *conn, struct kdbus_msg *msg);


static void kdbus_msg_release(struct kref *kref)
{
	struct kdbus_test_msg *msg = container_of(kref, struct kdbus_test_msg, kref);
	kfree(msg);
}


/* kdbus file operations */
static int kdbus_conn_open(struct inode *inode, struct file *file)
{
	struct kdbus_conn *conn;
	struct kdbus_ns *ns;
	struct kdbus_ep *ep;
	int i;
	int err;

	conn = kzalloc(sizeof(struct kdbus_conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	/* find and reference namespace */
	mutex_lock(&kdbus_subsys_lock);
	ns = idr_find(&kdbus_ns_major_idr, MAJOR(inode->i_rdev));
	if (!ns || ns->disconnected) {
		kfree(conn);
		mutex_unlock(&kdbus_subsys_lock);
		return -ENOENT;
	}
	conn->ns = kdbus_ns_ref(ns);
	file->private_data = conn;
	mutex_unlock(&kdbus_subsys_lock);

	/* control device node */
	if (MINOR(inode->i_rdev) == 0) {
		conn->type = KDBUS_CONN_CONTROL;
		file->private_data = conn;
		pr_info("opened control device '%s/control'\n",
			conn->ns->devpath);
		return 0;
	}

	/* find endpoint for device node */
	mutex_lock(&conn->ns->lock);
	ep = idr_find(&conn->ns->idr, MINOR(inode->i_rdev));
	if (!ep || ep->disconnected) {
		err = -ENOENT;
		goto err_unlock;
	}

	/* create endpoint connection */
	conn->type = KDBUS_CONN_EP;
	conn->ep = kdbus_ep_ref(ep);

	/* get and register new id for this connection */
	conn->id = conn->ep->bus->conn_id_next++;

	/* FIXME: get 64 bit working, this will fail for the 2^31th connection */
	/* use a hash table to get 64bit ids working properly, idr is the wrong
	 * thing to use here. */
	i = idr_alloc(&conn->ep->bus->conn_idr, conn, conn->id, 0, GFP_KERNEL);
	if (i >= 0 && conn->id != i) {
		idr_remove(&conn->ep->bus->conn_idr, i);
		err = -EEXIST;
		goto err_unlock;
	}

	mutex_init(&conn->msg_lock);
	INIT_LIST_HEAD(&conn->msg_list);

	list_add_tail(&conn->connection_entry, &connection_list);

	file->private_data = conn;
	mutex_unlock(&conn->ns->lock);

	pr_info("created endpoint bus connection %llu '%s/%s'\n",
		(unsigned long long)conn->id, conn->ns->devpath,
		conn->ep->bus->name);
	return 0;

err_unlock:
	mutex_unlock(&conn->ns->lock);
	kfree(conn);
	return err;
}

static int kdbus_conn_release(struct inode *inode, struct file *file)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_test_msg *msg;
	struct kdbus_msg_list_entry *msg_entry, *tmp_entry;

	switch (conn->type) {
	case KDBUS_CONN_NS_OWNER:
		break;

	case KDBUS_CONN_BUS_OWNER:
		kdbus_bus_disconnect(conn->bus_owner);
		kdbus_bus_unref(conn->bus_owner);
		break;

	case KDBUS_CONN_EP:
		kdbus_ep_unref(conn->ep);
		list_del(&conn->connection_entry);
		/* clean up any messages still left on this endpoint */
		mutex_lock(&conn->msg_lock);
		list_for_each_entry_safe(msg_entry, tmp_entry, &conn->msg_list, entry) {
			msg = msg_entry->msg;
			list_del(&msg_entry->entry);
			kfree(msg_entry);
			kref_put(&msg->kref, kdbus_msg_release);
		}
		mutex_unlock(&conn->msg_lock);

		break;

	default:
		break;
	}

	mutex_lock(&conn->ns->lock);
	kdbus_ns_unref(conn->ns);
	mutex_unlock(&conn->ns->lock);
	kfree(conn);
	return 0;
}

/* kdbus control device commands */
static long kdbus_conn_ioctl_control(struct file *file, unsigned int cmd,
				     void __user *argp)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_name name;
	struct kdbus_bus *bus = NULL;
	struct kdbus_ns *ns = NULL;
	int err;

	switch (cmd) {
	case KDBUS_CMD_BUS_CREATE:
		if (copy_from_user(&name, argp, sizeof(struct kdbus_cmd_name)))
			return -EFAULT;

		err = kdbus_bus_new(conn->ns, name.name,
				    0660, current_fsuid(), current_fsgid(),
				    &bus);
		if (err < 0)
			return err;

		/* turn the control fd into a new bus owner device */
		conn->type = KDBUS_CONN_BUS_OWNER;
		conn->bus_owner = bus;
		break;

#if 0	/* FIXME Don't know if we really want this... */
	case KDBUS_CMD_BUS_REMOVE:
		if (copy_from_user(&name, argp, sizeof(struct kdbus_cmd_name)))
			return -EFAULT;

		bus = kdbus_bus_find(name.name);
		if (!bus)
			return -EINVAL;
		kdbus_bus_disconnect(bus);	// FIXME needed?
		kdbus_bus_unref(bus);
		break;
#endif
	case KDBUS_CMD_NS_CREATE:
		if (copy_from_user(&name, argp, sizeof(struct kdbus_cmd_name)))
			return -EFAULT;

		err = kdbus_ns_new(kdbus_ns_init, name.name, &ns);
		if (err < 0) {
			pr_err("failed to create namespace %s, err=%i\n",
				name.name, err);
			return err;
		}
		break;

	case KDBUS_CMD_NS_REMOVE:
		if (copy_from_user(&name, argp, sizeof(struct kdbus_cmd_name)))
			return -EFAULT;

		ns = kdbus_ns_find(name.name);
		if (!ns)
			return -EINVAL;

		/* we can not remove the "default" namespace */
		if (ns == kdbus_ns_init)
			return -EINVAL;

		kdbus_ns_unref(ns);
		break;

	default:
		return -ENOTTY;
	}
	return 0;
}

/* kdbus bus endpoint commands */
static long kdbus_conn_ioctl_ep(struct file *file, unsigned int cmd,
				void __user *argp)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_name name;
	struct kdbus_msg *msg;
	struct kdbus_ep *ep;
	long err;

	/* We need a connection before we can do anything with an ioctl */
	if (!conn)
		return -EINVAL;

	switch (cmd) {
	case KDBUS_CMD_EP_CREATE:
		/* create a new endpoint for this bus */
		if (copy_from_user(&name, argp, sizeof(struct kdbus_cmd_name)))
			return -EFAULT;
		return kdbus_ep_new(conn->ep->bus, name.name,
				    0660, current_fsuid(), current_fsgid(),
				    NULL);

	case KDBUS_CMD_EP_REMOVE:
		/* remove an endpoint from this bus */
		if (copy_from_user(&name, argp, sizeof(struct kdbus_cmd_name)))
			return -EFAULT;
		ep = kdbus_ep_find(conn->bus_owner, name.name);
		if (!ep)
			return -EINVAL;

		return kdbus_ep_remove(ep);

	case KDBUS_CMD_EP_POLICY_SET:
		/* upload a policy for this bus */
		return -ENOSYS;

	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */
		return -ENOSYS;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */
		return -ENOSYS;

	case KDBUS_CMD_NAME_LIST:
		/* return all current well-known names */
		return -ENOSYS;

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */
		return -ENOSYS;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */
		return -ENOSYS;

	case KDBUS_CMD_MSG_SEND:
		/* send a message */
		err = kdbus_msg_new(conn, argp, &msg);
		if (err < 0)
			return err;
		return kdbus_msg_send(conn, msg);

	case KDBUS_CMD_MSG_RECV:
		/* receive a message, needs to be freed */
		return -ENOSYS;

	default:
		return -ENOTTY;
	}
}

static long kdbus_conn_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct kdbus_conn *conn = file->private_data;
	void __user *argp = (void __user *)arg;

	pr_info("%s, cmd=%d\n", __func__, cmd);
	switch (conn->type) {
	case KDBUS_CONN_CONTROL:
		pr_info("control ioctl\n");
		return kdbus_conn_ioctl_control(file, cmd, argp);

	case KDBUS_CONN_EP:
		pr_info("endpoint ioctl\n");
		return kdbus_conn_ioctl_ep(file, cmd, argp);

	default:
		pr_info("bad type\n");
		return -EINVAL;
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

	mutex_lock(&conn->msg_lock);
	if (!list_empty(&conn->msg_list))
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&conn->msg_lock);

	return 0;
}

static int kdbus_conn_mmap(struct file *file, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static ssize_t kdbus_conn_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_conn *temp_conn;
	struct kdbus_test_msg *msg;

	/* Only an endpoint can read/write data */
	if (conn->type != KDBUS_CONN_EP)
		return -EINVAL;

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
			list_add_tail(&msg_list_entry->entry, &temp_conn->msg_list);
			mutex_unlock(&temp_conn->msg_lock);
			/* wake up the other processes.  Hopefully... */
			wake_up_interruptible_all(&temp_conn->ep->wait);
		}
	}

	/* drop our reference on the message, as we are done with it */
	kref_put(&msg->kref, kdbus_msg_release);
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
		// FIXME, this will oops, need to use list_safe_loop()
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
		kref_put(&msg->kref, kdbus_msg_release);
	}

exit:
	mutex_unlock(&conn->msg_lock);
	return retval;
}

const struct file_operations kdbus_device_ops = {
	.owner =		THIS_MODULE,
	.open =			kdbus_conn_open,
	.release =		kdbus_conn_release,
	.unlocked_ioctl =	kdbus_conn_ioctl,
	.compat_ioctl =		kdbus_conn_ioctl,
	.poll = 		kdbus_conn_poll,
	.mmap =			kdbus_conn_mmap,
	.llseek =		noop_llseek,
	.write = 		kdbus_conn_write,
	.read =			kdbus_conn_read,
};

static void kdbus_msg_free(struct kdbus_msg *msg)
{
	kfree(msg);
}

static int kdbus_msg_new(struct kdbus_conn *conn, struct kdbus_msg __user *umsg,
			 struct kdbus_msg **msg)
{
	struct kdbus_msg *m;
	int err;

	m = kmalloc(sizeof(struct kdbus_msg), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	if (copy_from_user(m, umsg, sizeof(struct kdbus_msg))) {
		err = -EFAULT;
		goto out_err;
	}

	m->src_id = conn->id;
	m->msg_id = conn->ep->bus->msg_id_next++;
	*msg = m;
	return 0;
out_err:
	kdbus_msg_free(m);
	return err;
}

static int kdbus_msg_send(struct kdbus_conn *conn, struct kdbus_msg *msg)
{
	struct kdbus_conn *conn_dst;

	conn_dst = idr_find(&conn->ep->bus->conn_idr, msg->dst_id);
	if (!conn_dst)
		return -ENOENT;

	pr_info("sending message %llu from %llu to %llu\n",
		(unsigned long long)msg->msg_id,
		(unsigned long long)msg->src_id,
		(unsigned long long)msg->dst_id);

	kdbus_msg_free(msg);
	return 0;
}

static int __init kdbus_init(void)
{
	int err;

	err = bus_register(&kdbus_subsys);
	if (err < 0)
		return err;

	err = kdbus_ns_new(NULL, NULL, &kdbus_ns_init);
	if (err < 0) {
		bus_unregister(&kdbus_subsys);
		pr_err("failed to initialize err=%i\n", err);
		return err;
	}

	pr_info("initialized\n");
	return 0;
}

static void __exit kdbus_exit(void)
{
	kdbus_ns_unref(kdbus_ns_init);
	bus_unregister(&kdbus_subsys);
	pr_info("unloaded\n");
}

module_init(kdbus_init);
module_exit(kdbus_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kdbus interprocess message router");
MODULE_ALIAS_CHARDEV(KDBUS_CHAR_MAJOR, 0);
MODULE_ALIAS("devname:kdbus/control");
