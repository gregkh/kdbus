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

enum kdbus_handle_type {
	_KDBUS_HANDLE_NULL,
	KDBUS_HANDLE_CONTROL,		/* new fd of a control node */
	KDBUS_HANDLE_CONTROL_NS_OWNER,	/* fd to hold a namespace */
	KDBUS_HANDLE_CONTROL_BUS_OWNER,	/* fd to hold a bus */
	KDBUS_HANDLE_EP,		/* new fd of a bus node */
	KDBUS_HANDLE_EP_CONNECTED,	/* connection after HELLO */
	KDBUS_HANDLE_EP_DISCONNECTED,	/* closed connection */
	KDBUS_HANDLE_EP_OWNER,		/* fd to hold an endpoint */
};

/**
 * struct kdbus_handle - a handle to the kdbus system
 * @type	Type of this handle (KDBUS_HANDLE_*)
 * @ns		Namespace for this handle
 * @ns_owner:	The namespace this handle owns, in case @type
 * 		is KDBUS_HANDLE_CONTROL_NS_OWNER
 * @bus_owner:	The bus this handle owns, in case @type
 * 		is KDBUS_HANDLE_CONTROL_BUS_OWNER
 * @conn	The connection this handle owns, in case @type
 * 		is KDBUS_HANDLE_EP_CONNECTED
 * @ep		The endpoint this handle owns, in case @type
 * 		is KDBUS_HANDLE_EP or KDBUS_HANDLE_EP_OWNER
 */
struct kdbus_handle {
	enum kdbus_handle_type type;
	struct kdbus_ns *ns;
	union {
		struct kdbus_ns *ns_owner;
		struct kdbus_bus *bus_owner;
		struct kdbus_conn *conn;
		struct kdbus_ep *ep;
	};
};

static int kdbus_handle_open(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle;
	struct kdbus_ns *ns;
	struct kdbus_ep *ep;
	int ret;

	handle = kzalloc(sizeof(struct kdbus_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* find and reference namespace */
	ns = kdbus_ns_find_by_major(MAJOR(inode->i_rdev));
	if (!ns) {
		kfree(handle);
		return -ESHUTDOWN;
	}
	handle->ns = kdbus_ns_ref(ns);
	file->private_data = handle;

	/* control device node */
	if (MINOR(inode->i_rdev) == 0) {
		handle->type = KDBUS_HANDLE_CONTROL;
		return 0;
	}

	/* find endpoint for device node */
	mutex_lock(&handle->ns->lock);
	ep = idr_find(&handle->ns->idr, MINOR(inode->i_rdev));
	if (!ep || ep->disconnected) {
		ret = -ESHUTDOWN;
		goto exit_unlock;
	}

	/* create endpoint connection */
	handle->type = KDBUS_HANDLE_EP;
	handle->ep = kdbus_ep_ref(ep);
	mutex_unlock(&handle->ns->lock);
	return 0;

exit_unlock:
	mutex_unlock(&handle->ns->lock);
	kfree(handle);
	return ret;
}

static int kdbus_handle_release(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle = file->private_data;

	switch (handle->type) {
	case KDBUS_HANDLE_CONTROL_NS_OWNER:
		kdbus_ns_disconnect(handle->ns_owner);
		kdbus_ns_unref(handle->ns_owner);
		break;

	case KDBUS_HANDLE_CONTROL_BUS_OWNER:
		kdbus_bus_disconnect(handle->bus_owner);
		kdbus_bus_unref(handle->bus_owner);
		break;

	case KDBUS_HANDLE_EP_OWNER:
		kdbus_ep_disconnect(handle->ep);
		kdbus_ep_unref(handle->ep);
		break;

	case KDBUS_HANDLE_EP:
		kdbus_ep_unref(handle->ep);
		break;

	case KDBUS_HANDLE_EP_CONNECTED:
		kdbus_conn_disconnect(handle->conn);
		kdbus_conn_unref(handle->conn);
		break;

	default:
		break;
	}

	handle->type = KDBUS_HANDLE_EP_DISCONNECTED;
	kdbus_ns_unref(handle->ns);
	kfree(handle);

	return 0;
}

static bool kdbus_check_flags(u64 kernel_flags)
{
	/* The higher 32bit are considered 'incompatible
	 * flags'. Refuse them all for now */
	return kernel_flags <= 0xFFFFFFFFULL;
}

/* kdbus control device commands */
static long kdbus_handle_ioctl_control(struct file *file, unsigned int cmd,
				     void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_cmd_bus_make *bus_make = NULL;
	struct kdbus_cmd_ns_kmake *ns_kmake = NULL;
	struct kdbus_bus *bus = NULL;
	struct kdbus_ns *ns = NULL;
	umode_t mode = 0600;
	int ret;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE: {
		kgid_t gid = KGIDT_INIT(0);
		char *name;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_bus_make_user(buf, &bus_make, &name);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(bus_make->flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (bus_make->flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (bus_make->flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		ret = kdbus_bus_new(handle->ns, bus_make, name,
				    mode, current_fsuid(), gid, &bus);
		if (ret < 0)
			break;

		/* turn the control fd into a new bus owner device */
		handle->type = KDBUS_HANDLE_CONTROL_BUS_OWNER;
		handle->bus_owner = bus;
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
		handle->type = KDBUS_HANDLE_CONTROL_NS_OWNER;
		handle->ns_owner = ns;
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

	kfree(bus_make);
	kfree(ns_kmake);
	return ret;
}

/* kdbus endpoint make commands */
static long kdbus_handle_ioctl_ep(struct file *file, unsigned int cmd,
				  void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_cmd_ep_kmake *kmake = NULL;
	struct kdbus_cmd_hello *hello = NULL;
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

		ret = kdbus_ep_new(handle->ep->bus, kmake->name, mode,
				   current_fsuid(), gid,
				   kmake->make.flags & KDBUS_MAKE_POLICY_OPEN);

		handle->type = KDBUS_HANDLE_EP_OWNER;
		break;
	}

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
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

		ret = kdbus_conn_new(handle->ep, hello, &handle->conn);
		if (ret < 0)
			break;

		handle->type = KDBUS_HANDLE_EP_CONNECTED;

		if (copy_to_user(buf, hello, sizeof(struct kdbus_cmd_hello))) {
			kdbus_conn_unref(handle->conn);
			return -EFAULT;
		}

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
static long kdbus_handle_ioctl_ep_connected(struct file *file, unsigned int cmd,
					    void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_conn *conn = handle->conn;
	struct kdbus_bus *bus = conn->ep->bus;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_EP_POLICY_SET:
		/* upload a policy for this endpoint */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		if (!conn->ep->policy_db) {
			ret = kdbus_policy_db_new(&conn->ep->policy_db);
			if (ret < 0)
				return ret;
		}

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

	case KDBUS_CMD_CONN_INFO:
		/* return details about a specific well-known name */
		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_conn_info(bus->name_registry, conn, buf);
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

static long kdbus_handle_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct kdbus_handle *handle = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (handle->type) {
	case KDBUS_HANDLE_CONTROL:
		return kdbus_handle_ioctl_control(file, cmd, argp);

	case KDBUS_HANDLE_EP:
		return kdbus_handle_ioctl_ep(file, cmd, argp);

	case KDBUS_HANDLE_EP_CONNECTED:
		return kdbus_handle_ioctl_ep_connected(file, cmd, argp);

	default:
		return -EBADFD;
	}
}

static unsigned int kdbus_handle_poll(struct file *file,
				      struct poll_table_struct *wait)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_conn *conn;
	unsigned int mask = 0;
	bool disconnected;

	/* Only an endpoint can read/write data */
	if (handle->type != KDBUS_HANDLE_EP_CONNECTED)
		return POLLERR | POLLHUP;

	conn = handle->conn;

	poll_wait(file, &conn->ep->wait, wait);

	mutex_lock(&conn->lock);

	mutex_lock(&conn->ep->lock);
	disconnected = conn->ep->disconnected;
	mutex_unlock(&conn->ep->lock);

	if (unlikely(disconnected))
		mask |= POLLERR | POLLHUP;
	else if (!list_empty(&conn->msg_list))
		mask |= POLLIN | POLLRDNORM;

	mutex_unlock(&conn->lock);

	return mask;
}

static int kdbus_handle_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kdbus_handle *handle = file->private_data;

	if (handle->type != KDBUS_HANDLE_EP_CONNECTED)
		return -EPERM;

	if (handle->conn->flags & KDBUS_HELLO_STARTER)
		return -EPERM;

	return kdbus_pool_mmap(handle->conn->pool, vma);
}

const struct file_operations kdbus_device_ops = {
	.owner =		THIS_MODULE,
	.open =			kdbus_handle_open,
	.release =		kdbus_handle_release,
	.poll =			kdbus_handle_poll,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	kdbus_handle_ioctl,
	.mmap =			kdbus_handle_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		kdbus_handle_ioctl,
#endif
};
