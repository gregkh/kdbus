/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
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
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <uapi/linux/major.h>
#include "kdbus.h"

#include "kdbus_internal.h"

static void kdbus_conn_scan_timeout(struct kdbus_conn *conn)
{
	struct kdbus_msg_list_entry *entry, *tmp;
	u64 deadline = -1;
	struct timespec ts;
	uint64_t now;

	ktime_get_ts(&ts);
	now = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;

	mutex_lock(&conn->msg_lock);
	list_for_each_entry_safe(entry, tmp, &conn->msg_list, list) {
		struct kdbus_kmsg *kmsg = entry->kmsg;

		if (kmsg->deadline == 0)
			continue;

		if (kmsg->deadline <= now) {
			kdbus_notify_reply_timeout(conn->ep, &kmsg->msg);
			kdbus_kmsg_unref(entry->kmsg);
			list_del(&entry->list);
			kfree(entry);
		} else if (kmsg->deadline < deadline) {
			deadline = kmsg->deadline;
		}
	}
	mutex_unlock(&conn->msg_lock);

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

void kdbus_conn_schedule_timeout_scan(struct kdbus_conn *conn)
{
	schedule_work(&conn->work);
}

static void kdbus_conn_timer_func(unsigned long val)
{
	struct kdbus_conn *conn = (struct kdbus_conn *) val;
	kdbus_conn_schedule_timeout_scan(conn);
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
		ret = -ENOENT;
		goto err_unlock;
	}

	/* create endpoint connection */
	conn->type = KDBUS_CONN_EP;
	conn->ep = kdbus_ep_ref(ep);

	/* get and register new id for this connection */
	conn->id = conn->ep->bus->conn_id_next++;

	/* add this connection to hash table */
	hash_add(conn->ep->bus->conn_hash, &conn->hentry, conn->id);

	mutex_init(&conn->msg_lock);
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

	conn->creds.uid = current_uid();
	conn->creds.gid = current_gid();
	conn->creds.pid = current->pid;
	conn->creds.tid = current->tgid;

	pr_info("created endpoint bus connection %llu '%s/%s'\n",
		(unsigned long long)conn->id, conn->ns->devpath,
		conn->ep->bus->name);

	ret = kdbus_notify_id_change(conn->ep, KDBUS_MSG_ID_ADD, conn->id, 0);
	if (ret < 0)
		return ret;

	return 0;

err_unlock:
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
		struct kdbus_msg_list_entry *entry, *tmp;

		hash_del(&conn->hentry);
		list_del(&conn->connection_entry);
		/* clean up any messages still left on this endpoint */
		mutex_lock(&conn->msg_lock);
		list_for_each_entry_safe(entry, tmp, &conn->msg_list, list) {
			struct kdbus_kmsg *kmsg = entry->kmsg;

#if 0
			struct kdbus_msg *msg = &kmsg->msg;
			if (msg->dst_id != KDBUS_DST_ID_BROADCAST &&
			    msg->src_id != conn->id)
				kdbus_notify_reply_dead(conn->ep, msg);
#endif

			kdbus_kmsg_unref(kmsg);
			list_del(&entry->list);
			kfree(entry);
		}
		mutex_unlock(&conn->msg_lock);

		del_timer(&conn->timer);
		cancel_work_sync(&conn->work);

		bus = conn->ep->bus;
		kdbus_name_remove_by_conn(bus->name_registry, conn);
		kdbus_ep_unref(conn->ep);

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

static int kdbus_fname_user(void __user *buf, struct kdbus_cmd_fname **fname)
{
	u64 size;
	struct kdbus_cmd_fname *fn;

	if (kdbus_size_user(size, buf, struct kdbus_cmd_fname, size))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_fname) + 2)
		return -EINVAL;

	if (size > sizeof(struct kdbus_cmd_fname) + 64)
		return -ENAMETOOLONG;

	fn = memdup_user(buf, size);
	if (IS_ERR(fn))
		return PTR_ERR(fn);

	*fname = fn;

	return 0;
}

/* kdbus control device commands */
static long kdbus_conn_ioctl_control(struct file *file, unsigned int cmd,
				     void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_fname *fname = NULL;
	struct kdbus_bus *bus = NULL;
	struct kdbus_ns *ns = NULL;
	umode_t mode = 0;
	int ret;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE:
		ret = kdbus_fname_user(buf, &fname);
		if (ret < 0)
			break;

		if (!check_flags(fname->kernel_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (fname->flags & KDBUS_CMD_FNAME_ACCESS_WORLD)
			mode = 0666;
		else if (fname->flags & KDBUS_CMD_FNAME_ACCESS_GROUP)
			mode = 0660;

		ret = kdbus_bus_new(conn->ns, fname->name, fname->flags,
				    mode, current_fsuid(), current_fsgid(), &bus);
		if (ret < 0)
			break;

		/* turn the control fd into a new bus owner device */
		conn->type = KDBUS_CONN_BUS_OWNER;
		conn->bus_owner = bus;

		break;

	case KDBUS_CMD_NS_MAKE:
		ret = kdbus_fname_user(buf, &fname);
		if (ret < 0)
			break;

		if (!check_flags(fname->kernel_flags))
			return -ENOTSUPP;

		if (fname->flags & KDBUS_CMD_FNAME_ACCESS_WORLD)
			mode = 0666;
		else if (fname->flags & KDBUS_CMD_FNAME_ACCESS_GROUP)
			mode = 0660;

		ret = kdbus_ns_new(kdbus_ns_init, fname->name, mode, &ns);
		if (ret < 0) {
			pr_err("failed to create namespace %s, ret=%i\n",
			       fname->name, ret);
			return ret;
		}

		/* turn the control fd into a new ns owner device */
		conn->type = KDBUS_CONN_NS_OWNER;
		conn->ns_owner = ns;

		break;

	case KDBUS_CMD_BUS_POLICY_SET:
		ret = -ENOSYS;

		break;

	default:
		ret = -ENOTTY;

		break;
	}

	kfree(fname);
	return ret;
}

/* kdbus bus endpoint commands */
static long kdbus_conn_ioctl_ep(struct file *file, unsigned int cmd,
				void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_fname *fname = NULL;
	struct kdbus_kmsg *kmsg;
	struct kdbus_bus *bus;
	long ret = 0;

	/* We need a connection before we can do anything with an ioctl */
	if (!conn)
		return -EINVAL;

	switch (cmd) {
	case KDBUS_CMD_EP_MAKE: {
		u64 size;
		umode_t mode = 0;

		/* create a new endpoint for this bus, and turn this
		 * fd into a reference to it */
		if (kdbus_size_user(size, buf, struct kdbus_cmd_fname, size)) {
			ret = -EFAULT;
			break;
		}

		if (size < sizeof(struct kdbus_cmd_fname) + 2) {
			ret = -EINVAL;
			break;
		}

		if (size > sizeof(struct kdbus_cmd_fname) + 64) {
			ret = -ENAMETOOLONG;
			break;
		}

		fname = memdup_user(buf, size);
		if (IS_ERR(fname)) {
			ret = PTR_ERR(fname);
			fname = NULL;
			break;
		}

		if (!check_flags(fname->kernel_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (fname->flags & KDBUS_CMD_FNAME_ACCESS_WORLD)
			mode = 0666;
		else if (fname->flags & KDBUS_CMD_FNAME_ACCESS_GROUP)
			mode = 0660;

		ret = kdbus_ep_new(conn->ep->bus, fname->name, mode,
				   current_fsuid(), current_fsgid(), NULL);

		break;
	}

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
		struct kdbus_cmd_hello hello;

		if (conn->active) {
			ret = -EBUSY;
			break;
		}

		if (copy_from_user(&hello, buf, sizeof(hello))) {
			ret = -EFAULT;
			break;
		}

		if (!check_flags(hello.kernel_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		hello.bus_flags = 0; /* FIXME */
		hello.id = conn->id;

		if (copy_to_user(buf, &hello, sizeof(hello))) {
			ret = -EFAULT;
			break;
		}

		conn->active = true;
		conn->starter = hello.kernel_flags & KDBUS_CMD_HELLO_STARTER;

		break;
	}

	case KDBUS_CMD_EP_POLICY_SET:
		/* upload a policy for this endpoint */
		if (!conn->ep->policy_db)
			return -EINVAL;

		ret = kdbus_policy_set_from_user(conn->ep->policy_db, buf);

		break;

	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */
		bus = conn->ep->bus;
		ret = kdbus_name_acquire(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */
		bus = conn->ep->bus;
		ret = kdbus_name_release(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_NAME_LIST:
		/* return all current well-known names */
		bus = conn->ep->bus;
		ret = kdbus_name_list(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_NAME_QUERY:
		/* return details about a specific well-known name */
		bus = conn->ep->bus;
		ret =kdbus_name_query(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */
		ret = -ENOSYS;

		break;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */
		ret = -ENOSYS;

		break;

	case KDBUS_CMD_MONITOR:
		/* turn on/turn off monitor mode */
		ret = -ENOSYS;

		break;

	case KDBUS_CMD_MSG_SEND:
		/* send a message */
		ret = kdbus_kmsg_new_from_user(buf, &kmsg);
		if (ret < 0)
			break;

		ret = kdbus_kmsg_send(conn->ep, &kmsg);
		kdbus_kmsg_unref(kmsg);

		break;

	case KDBUS_CMD_MSG_RECV:
		/* receive a message */
		ret = kdbus_kmsg_recv(conn, buf);

		break;

	default:
		ret = -ENOTTY;

		break;
	}

	kfree(fname);

	return ret;
}

static long kdbus_conn_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct kdbus_conn *conn = file->private_data;
	void __user *argp = (void __user *)arg;

	//pr_info("%s, cmd=%d\n", __func__, cmd);
	switch (conn->type) {
	case KDBUS_CONN_CONTROL:
		//pr_info("control ioctl\n");
		return kdbus_conn_ioctl_control(file, cmd, argp);

	case KDBUS_CONN_EP:
		//pr_info("endpoint ioctl\n");
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
