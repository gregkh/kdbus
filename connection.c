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
#include <linux/hashtable.h>
#include <uapi/linux/major.h>

#include "connection.h"
#include "message.h"
#include "notify.h"
#include "ns.h"
#include "ep.h"
#include "bus.h"
#include "match.h"
#include "names.h"
#include "policy.h"

int kdbus_conn_add_size_allocation(struct kdbus_conn *conn, u64 size)
{
	int ret = 0;

	if (!conn)
		return 0;

	mutex_lock(&conn->accounting_lock);
	if (conn->allocated_size + size > KDBUS_CONN_MAX_ALLOCATED_BYTES)
		ret = -EOVERFLOW;
	else
		conn->allocated_size += size;
	mutex_unlock(&conn->accounting_lock);

	return ret;
}

void kdbus_conn_sub_size_allocation(struct kdbus_conn *conn, u64 size)
{
	if (!conn)
		return;

	mutex_lock(&conn->accounting_lock);
	conn->allocated_size -= size;
	mutex_unlock(&conn->accounting_lock);
}

static void kdbus_conn_scan_timeout(struct kdbus_conn *conn)
{
	struct kdbus_msg_list_entry *entry, *tmp;
	u64 deadline = -1;
	struct timespec ts;
	uint64_t now;

	ktime_get_ts(&ts);
	now = timespec_to_ns(&ts);

	mutex_lock(&conn->msg_lock);
	list_for_each_entry_safe(entry, tmp, &conn->msg_list, entry) {
		struct kdbus_kmsg *kmsg = entry->kmsg;

		if (kmsg->deadline_ns == 0)
			continue;

		if (kmsg->deadline_ns <= now) {
			if (kmsg->msg.flags & KDBUS_MSG_FLAGS_EXPECT_REPLY)
				kdbus_notify_reply_timeout(conn->ep, &kmsg->msg);
			kdbus_kmsg_unref(entry->kmsg);
			list_del(&entry->entry);
			kfree(entry);
		} else if (kmsg->deadline_ns < deadline) {
			deadline = kmsg->deadline_ns;
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
		return -ESHUTDOWN;
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
		ret = -ESHUTDOWN;
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
		struct list_head list;

		INIT_LIST_HEAD(&list);

		hash_del(&conn->hentry);
		list_del(&conn->connection_entry);
		/* clean up any messages still left on this endpoint */
		mutex_lock(&conn->msg_lock);
		list_for_each_entry_safe(entry, tmp, &conn->msg_list, entry) {
			struct kdbus_kmsg *kmsg = entry->kmsg;
			struct kdbus_msg *msg = &kmsg->msg;

			list_del(&entry->entry);

			/*
			 * calling kdbus_notify_reply_dead() with msg_lock held
			 * causes a lockdep warning, so let's re-link those
			 * messages into a temporary list and handle it later.
			 */
			if (msg->src_id != conn->id &&
			    msg->flags & KDBUS_MSG_FLAGS_EXPECT_REPLY) {
				list_add_tail(&entry->entry, &list);
			} else {
				kdbus_kmsg_unref(kmsg);
				kfree(entry);
			}
		}
		mutex_unlock(&conn->msg_lock);

		list_for_each_entry_safe(entry, tmp, &list, entry) {
			struct kdbus_kmsg *kmsg = entry->kmsg;
			struct kdbus_msg *msg = &kmsg->msg;

			kdbus_notify_reply_dead(conn->ep, msg);
			kdbus_kmsg_unref(kmsg);
			kfree(entry);
		}

		del_timer(&conn->timer);
		cancel_work_sync(&conn->work);

		bus = conn->ep->bus;
		kdbus_name_remove_by_conn(bus->name_registry, conn);
		if (conn->ep->policy_db)
			kdbus_policy_db_remove_conn(conn->ep->policy_db, conn);
		kdbus_match_db_unref(conn->match_db);
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

/* kdbus control device commands */
static long kdbus_conn_ioctl_control(struct file *file, unsigned int cmd,
				     void __user *buf)
{
	struct kdbus_conn *conn = file->private_data;
	struct kdbus_cmd_bus_kmake *bus_kmake = NULL;
	struct kdbus_cmd_ns_kmake *ns_kmake = NULL;
	struct kdbus_bus *bus = NULL;
	struct kdbus_ns *ns = NULL;
	umode_t mode = 0;
	int ret;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE:
		ret = kdbus_bus_make_user(buf, &bus_kmake);
		if (ret < 0)
			break;

		if (!check_flags(bus_kmake->make.flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (bus_kmake->make.flags & KDBUS_ACCESS_WORLD)
			mode = 0666;
		else if (bus_kmake->make.flags & KDBUS_ACCESS_GROUP)
			mode = 0660;

		ret = kdbus_bus_new(conn->ns, bus_kmake, mode, current_fsuid(),
				    current_fsgid(), &bus);
		if (ret < 0)
			break;

		/* turn the control fd into a new bus owner device */
		conn->type = KDBUS_CONN_BUS_OWNER;
		conn->bus_owner = bus;

		break;

	case KDBUS_CMD_NS_MAKE:
		ret = kdbus_ns_kmake_user(buf, &ns_kmake);
		if (ret < 0)
			break;

		if (!check_flags(ns_kmake->make.flags))
			return -ENOTSUPP;

		if (ns_kmake->make.flags & KDBUS_ACCESS_WORLD)
			mode = 0666;
		else if (ns_kmake->make.flags & KDBUS_ACCESS_GROUP)
			mode = 0660;

		ret = kdbus_ns_new(kdbus_ns_init, ns_kmake->name, mode, &ns);
		if (ret < 0)
			return ret;

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
	struct kdbus_kmsg *kmsg;
	struct kdbus_bus *bus;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_EP_MAKE: {
		umode_t mode = 0;

		ret = kdbus_ep_kmake_user(buf, &kmake);
		if (ret < 0)
			break;

		if (!check_flags(kmake->make.flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (kmake->make.flags & KDBUS_ACCESS_WORLD)
			mode = 0666;
		else if (kmake->make.flags & KDBUS_ACCESS_GROUP)
			mode = 0660;

		ret = kdbus_ep_new(conn->ep->bus, kmake->name, mode,
			current_fsuid(), current_fsgid(),
			kmake->make.flags & KDBUS_POLICY_OPEN);

		break;
	}

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
		struct kdbus_cmd_hello hello;

		if (conn->active) {
			ret = -EISCONN;
			break;
		}

		if (copy_from_user(&hello, buf, sizeof(hello))) {
			ret = -EFAULT;
			break;
		}

		if (!check_flags(hello.conn_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		conn->flags = hello.conn_flags;
		hello.bus_flags = conn->ep->bus->bus_flags;
		hello.bloom_size = conn->ep->bus->bloom_size;
		hello.id = conn->id;

		if (copy_to_user(buf, &hello, sizeof(hello))) {
			ret = -EFAULT;
			break;
		}

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
		bus = conn->ep->bus;
		ret = kdbus_cmd_name_acquire(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */
		bus = conn->ep->bus;
		ret = kdbus_cmd_name_release(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_NAME_LIST:
		/* return all current well-known names */
		bus = conn->ep->bus;
		ret = kdbus_cmd_name_list(bus->name_registry, conn, buf);

		break;

	case KDBUS_CMD_NAME_QUERY:
		/* return details about a specific well-known name */
		bus = conn->ep->bus;
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

	case KDBUS_CMD_MSG_SEND:
		/* send a message */
		ret = kdbus_kmsg_new_from_user(conn, buf, &kmsg);
		if (ret < 0)
			break;

		ret = kdbus_kmsg_send(conn->ep, conn, kmsg);
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

	kfree(kmake);

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
	.poll =			kdbus_conn_poll,
	.llseek =		noop_llseek,
};
