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
#include <uapi/linux/major.h>
#include "kdbus.h"

#include "kdbus_internal.h"

/* kdbus sysfs subsystem */
struct bus_type kdbus_subsys = {
	.name = "kdbus",
};

/* kdbus initial namespace */
static struct kdbus_ns *kdbus_ns_init;

/* map of majors to namespaces */
DEFINE_IDR(kdbus_ns_major_idr);

/* namespace list lock */
DEFINE_MUTEX(kdbus_subsys_lock);

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
	INIT_LIST_HEAD(&conn->names_list);
	INIT_LIST_HEAD(&conn->names_queue_list);
	INIT_LIST_HEAD(&conn->connection_entry);

	list_add_tail(&conn->connection_entry, &conn->ep->connection_list);

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
	struct kdbus_bus *bus;

	switch (conn->type) {
	case KDBUS_CONN_NS_OWNER:
		break;

	case KDBUS_CONN_BUS_OWNER:
		kdbus_bus_disconnect(conn->bus_owner);
		kdbus_bus_unref(conn->bus_owner);
		break;

	case KDBUS_CONN_EP: {
		struct kdbus_msg_list_entry *entry, *tmp;

 		bus = conn->ep->bus;
		kdbus_name_remove_by_conn(bus->name_registry, conn);
		kdbus_ep_unref(conn->ep);

		//list_del(&conn->connection_entry);

		/* clean up any messages still left on this endpoint */
		mutex_lock(&conn->msg_lock);
		list_for_each_entry_safe(entry, tmp, &conn->msg_list, list) {
			list_del(&entry->list);
			kdbus_kmsg_unref(entry->kmsg);
			kfree(entry);
		}
		mutex_unlock(&conn->msg_lock);

		break;
	}

	default:
		break;
	}

	mutex_lock(&conn->ns->lock);
	kdbus_ns_unref(conn->ns);
	mutex_unlock(&conn->ns->lock);
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
				     void __user *argp)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_fname fname;
	struct kdbus_bus *bus = NULL;
	struct kdbus_ns *ns = NULL;
	int err;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE:
		if (copy_from_user(&fname, argp, sizeof(struct kdbus_cmd_fname)))
			return -EFAULT;

		if (!check_flags(fname.kernel_flags))
			return -ENOTSUPP;

		err = kdbus_bus_new(conn->ns, fname.name, fname.bus_flags, fname.mode,
				    current_fsuid(), current_fsgid(),
				    &bus);
		if (err < 0)
			return err;

		/* turn the control fd into a new bus owner device */
		conn->type = KDBUS_CONN_BUS_OWNER;
		conn->bus_owner = bus;

		break;

	case KDBUS_CMD_NS_MAKE:
		if (copy_from_user(&fname, argp, sizeof(struct kdbus_cmd_fname)))
			return -EFAULT;

		if (!check_flags(fname.kernel_flags))
			return -ENOTSUPP;

		err = kdbus_ns_new(kdbus_ns_init, fname.name, fname.mode, &ns);
		if (err < 0) {
			pr_err("failed to create namespace %s, err=%i\n",
				fname.name, err);
			return err;
		}

		/* turn the control fd into a new ns owner device */
		conn->type = KDBUS_CONN_NS_OWNER;
		conn->ns_owner = ns;

		break;

	case KDBUS_CMD_BUS_POLICY_SET:
		return -ENOSYS;

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
	struct kdbus_cmd_fname fname;
	struct kdbus_kmsg *kmsg;
	struct kdbus_bus *bus;
	long err;

	/* We need a connection before we can do anything with an ioctl */
	if (!conn)
		return -EINVAL;

	switch (cmd) {
	case KDBUS_CMD_EP_MAKE:
		/* create a new endpoint for this bus, and turn this
		 * fd into a reference to it */
		if (copy_from_user(&fname, argp, sizeof(fname)))
			return -EFAULT;

		if (!check_flags(fname.kernel_flags))
			return -ENOTSUPP;

		return kdbus_ep_new(conn->ep->bus, fname.name, fname.mode,
				    current_fsuid(), current_fsgid(),
				    NULL);

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
		struct kdbus_cmd_hello hello;

		if (conn->active)
			return -EBUSY;

		if (copy_from_user(&hello, argp, sizeof(hello)))
			return -EFAULT;

		if (!check_flags(hello.kernel_flags))
			return -ENOTSUPP;

		hello.id = conn->id;

		if (copy_to_user(argp, &hello, sizeof(hello)) < 0)
			return -EFAULT;

		conn->active = true;
		break;
	}

	case KDBUS_CMD_EP_POLICY_SET:
		/* upload a policy for this bus */
		return -ENOSYS;

	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */
		bus = conn->ep->bus;
		return kdbus_name_acquire(bus->name_registry, conn, argp);

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */
		bus = conn->ep->bus;
		return kdbus_name_release(bus->name_registry, conn, argp);

	case KDBUS_CMD_NAME_LIST:
		/* return all current well-known names */
		bus = conn->ep->bus;
		return kdbus_name_list(bus->name_registry, conn, argp);

	case KDBUS_CMD_NAME_QUERY:
		/* return details about a specific well-known name */
		bus = conn->ep->bus;
		return kdbus_name_query(bus->name_registry, conn, argp);

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */
		return -ENOSYS;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */
		return -ENOSYS;

	case KDBUS_CMD_MONITOR:
		/* turn on/turn off monitor mode */
		return -ENOSYS;

	case KDBUS_CMD_MSG_SEND:
		/* send a message */
		err = kdbus_kmsg_new_from_user(conn, argp, &kmsg);
		if (err < 0)
			return err;
		err = kdbus_kmsg_send(conn->ep, kmsg);
		kdbus_kmsg_unref(kmsg);
		return err;

	case KDBUS_CMD_MSG_RECV:
		/* receive a message */
		return kdbus_kmsg_recv(conn, argp);

	default:
		return -ENOTTY;
	}

	return 0;
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

	return mask;
}

const struct file_operations kdbus_device_ops = {
	.owner =		THIS_MODULE,
	.open =			kdbus_conn_open,
	.release =		kdbus_conn_release,
	.unlocked_ioctl =	kdbus_conn_ioctl,
	.compat_ioctl =		kdbus_conn_ioctl,
	.poll = 		kdbus_conn_poll,
	.llseek =		noop_llseek,
};
static int __init kdbus_init(void)
{
	int err;

	err = bus_register(&kdbus_subsys);
	if (err < 0)
		return err;

	err = kdbus_ns_new(NULL, NULL, 0, &kdbus_ns_init);
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
