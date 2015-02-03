/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 * Copyright (C) 2014 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "handle.h"
#include "item.h"
#include "match.h"
#include "message.h"
#include "names.h"
#include "domain.h"
#include "policy.h"

static int kdbus_args_verify(struct kdbus_args *args)
{
	struct kdbus_item *item;
	size_t i;
	int ret;

	KDBUS_ITEMS_FOREACH(item, args->items, args->items_size) {
		struct kdbus_arg *arg = NULL;

		if (!KDBUS_ITEM_VALID(item, args->items, args->items_size))
			return -EINVAL;

		for (i = 0; i < args->argc; ++i)
			if (args->argv[i].type == item->type)
				break;
		if (i >= args->argc)
			return -EINVAL;

		arg = &args->argv[i];

		ret = kdbus_item_validate(item);
		if (ret < 0)
			return ret;

		if (arg->item && !arg->multiple)
			return -EINVAL;

		arg->item = item;
	}

	if (!KDBUS_ITEMS_END(item, args->items, args->items_size))
		return -EINVAL;

	for (i = 0; i < args->argc; ++i)
		if (args->argv[i].mandatory && !args->argv[i].item)
			return -EINVAL;

	return 0;
}

static int kdbus_args_negotiate(struct kdbus_args *args)
{
	struct kdbus_item __user *user;
	struct kdbus_item *negotiation;
	size_t i, j, num;

	/*
	 * If KDBUS_FLAG_NEGOTIATE is set, we overwrite the flags field with
	 * the set of supported flags. Furthermore, if an KDBUS_ITEM_NEGOTIATE
	 * item is passed, we iterate its payload (array of u64, each set to an
	 * item type) and clear all unsupported item-types to 0.
	 * The caller might do this recursively, if other flags or objects are
	 * embedded in the payload itself.
	 */

	if (!(args->cmd->flags & KDBUS_FLAG_NEGOTIATE))
		return 0;

	if (put_user(args->allowed_flags, &args->user->flags))
		return -EFAULT;

	if (args->argc < 1 || args->argv[0].type != KDBUS_ITEM_NEGOTIATE)
		return 0;

	negotiation = args->argv[0].item;
	if (!negotiation)
		return 0;

	user = (void*)((u8 __user *)args->user +
			((u8 *)negotiation - (u8 *)args->cmd));
	num = KDBUS_ITEM_PAYLOAD_SIZE(negotiation) / sizeof(u64);

	for (i = 0; i < num; ++i) {
		for (j = 0; j < args->argc; ++j)
			if (negotiation->data64[i] == args->argv[j].type)
				break;

		if (j < args->argc)
			continue;

		/* this item is not supported, clear it out */
		negotiation->data64[i] = 0;
		if (put_user(negotiation->data64[i], &user->data64[i]))
			return -EFAULT;
	}

	return 0;
}

int __kdbus_args_parse(struct kdbus_args *args, void __user *argp,
		       size_t type_size, size_t items_offset, void **out)
{
	int ret;

	args->cmd = kdbus_memdup_user(argp, type_size, KDBUS_CMD_MAX_SIZE);
	if (IS_ERR(args->cmd))
		return PTR_ERR(args->cmd);

	args->cmd->return_flags = 0;
	args->user = argp;
	args->items = (void*)((u8 *)args->cmd + items_offset);
	args->items_size = args->cmd->size - items_offset;

	if (args->cmd->flags & ~args->allowed_flags) {
		ret = -EINVAL;
		goto error;
	}

	ret = kdbus_args_verify(args);
	if (ret < 0)
		goto error;

	ret = kdbus_args_negotiate(args);
	if (ret < 0)
		goto error;

	*out = args->cmd;
	return 0;

error:
	return kdbus_args_clear(args, ret);
}

int kdbus_args_clear(struct kdbus_args *args, int ret)
{
	if (!args)
		return ret;

	if (!IS_ERR_OR_NULL(args->cmd)) {
		if (put_user(args->cmd->return_flags,
			     &args->user->return_flags))
			ret = -EFAULT;
		kfree(args->cmd);
		args->cmd = NULL;
	}

	return ret;
}

/**
 * enum kdbus_handle_ep_type - type an endpoint handle can be of
 * @KDBUS_HANDLE_EP_NONE:	New file descriptor on an endpoint
 * @KDBUS_HANDLE_EP_CONNECTED:	An endpoint connection after HELLO
 * @KDBUS_HANDLE_EP_OWNER:	File descriptor to hold an endpoint
 */
enum kdbus_handle_ep_type {
	KDBUS_HANDLE_EP_NONE,
	KDBUS_HANDLE_EP_CONNECTED,
	KDBUS_HANDLE_EP_OWNER,
};

/**
 * struct kdbus_handle_ep - an endpoint handle to the kdbus system
 * @lock:		Handle lock
 * @ep:			The endpoint for this handle
 * @type:		Type of this handle (KDBUS_HANDLE_EP_*)
 * @conn:		The connection this handle owns, in case @type
 *			is KDBUS_HANDLE_EP_CONNECTED
 * @ep_owner:		The endpoint this handle owns, in case @type
 *			is KDBUS_HANDLE_EP_OWNER
 * @privileged:		Flag to mark a handle as privileged
 */
struct kdbus_handle_ep {
	struct mutex lock;
	struct kdbus_ep *ep;

	enum kdbus_handle_ep_type type;
	union {
		struct kdbus_conn *conn;
		struct kdbus_ep *ep_owner;
	};

	bool privileged:1;
};

static int handle_ep_open(struct inode *inode, struct file *file)
{
	struct kdbus_handle_ep *handle;
	struct kdbus_domain *domain;
	struct kdbus_node *node;
	struct kdbus_bus *bus;
	int ret;

	/* kdbusfs stores the kdbus_node in i_private */
	node = inode->i_private;
	if (!kdbus_node_acquire(node))
		return -ESHUTDOWN;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle) {
		ret = -ENOMEM;
		goto exit_node;
	}

	mutex_init(&handle->lock);
	handle->ep = kdbus_ep_ref(kdbus_ep_from_node(node));
	handle->type = KDBUS_HANDLE_EP_NONE;

	domain = handle->ep->bus->domain;
	bus = handle->ep->bus;

	/*
	 * A connection is privileged if it is opened on an endpoint without
	 * custom policy and either:
	 *   * the user has CAP_IPC_OWNER in the domain user namespace
	 * or
	 *   * the callers euid matches the uid of the bus creator
	 */
	if (!handle->ep->has_policy &&
	    (ns_capable(domain->user_namespace, CAP_IPC_OWNER) ||
	     uid_eq(file->f_cred->euid, bus->node.uid)))
		handle->privileged = true;

	file->private_data = handle;
	kdbus_node_release(node);

	return 0;

exit_node:
	kdbus_node_release(node);
	return ret;
}

static int handle_ep_release(struct inode *inode, struct file *file)
{
	struct kdbus_handle_ep *handle = file->private_data;

	switch (handle->type) {
	case KDBUS_HANDLE_EP_OWNER:
		kdbus_ep_deactivate(handle->ep_owner);
		kdbus_ep_unref(handle->ep_owner);
		break;

	case KDBUS_HANDLE_EP_CONNECTED:
		kdbus_conn_disconnect(handle->conn, false);
		kdbus_conn_unref(handle->conn);
		break;

	case KDBUS_HANDLE_EP_NONE:
		/* nothing to clean up */
		break;
	}

	kdbus_ep_unref(handle->ep);
	kfree(handle);

	return 0;
}

/* kdbus endpoint make commands */
static long handle_ep_ioctl_none(struct file *file, unsigned int cmd,
				 void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	int ret = 0;

	lockdep_assert_held(&handle->lock);
	if (WARN_ON(handle->type != KDBUS_HANDLE_EP_NONE))
		return -EBADFD;

	switch (cmd) {
	case KDBUS_CMD_ENDPOINT_MAKE: {
		struct kdbus_ep *ep;

		/* creating custom endpoints is a privileged operation */
		if (!handle->privileged)
			return -EPERM;

		ep = kdbus_cmd_ep_make(handle->ep->bus, buf);
		if (IS_ERR(ep))
			return PTR_ERR(ep);

		handle->type = KDBUS_HANDLE_EP_OWNER;
		handle->ep_owner = ep;
		break;
	}

	case KDBUS_CMD_HELLO: {
		struct kdbus_conn *conn;

		conn = kdbus_cmd_hello(handle->ep, handle->privileged, buf);
		if (IS_ERR(conn))
			return PTR_ERR(conn);

		handle->type = KDBUS_HANDLE_EP_CONNECTED;
		handle->conn = conn;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

/* kdbus endpoint commands for connected peers */
static long handle_ep_ioctl_connected(struct file *file, unsigned int command,
				      void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	struct kdbus_conn *conn = handle->conn;
	struct kdbus_conn *release_conn = NULL;
	int ret;

	release_conn = conn;
	ret = kdbus_conn_acquire(release_conn);
	if (ret < 0)
		return ret;

	switch (command) {
	case KDBUS_CMD_BYEBYE:
		/*
		 * BYEBYE is special; we must not acquire a connection when
		 * calling into kdbus_conn_disconnect() or we will deadlock,
		 * because kdbus_conn_disconnect() will wait for all acquired
		 * references to be dropped.
		 */
		kdbus_conn_release(release_conn);
		release_conn = NULL;
		ret = kdbus_cmd_byebye_unlocked(conn, buf);
		break;
	case KDBUS_CMD_NAME_ACQUIRE:
		ret = kdbus_cmd_name_acquire(conn, buf);
		break;
	case KDBUS_CMD_NAME_RELEASE:
		ret = kdbus_cmd_name_release(conn, buf);
		break;
	case KDBUS_CMD_LIST:
		ret = kdbus_cmd_list(conn, buf);
		break;
	case KDBUS_CMD_CONN_INFO:
		ret = kdbus_cmd_conn_info(conn, buf);
		break;
	case KDBUS_CMD_BUS_CREATOR_INFO:
		ret = kdbus_cmd_bus_creator_info(conn, buf);
		break;
	case KDBUS_CMD_UPDATE:
		ret = kdbus_cmd_update(conn, buf);
		break;
	case KDBUS_CMD_MATCH_ADD:
		ret = kdbus_cmd_match_add(conn, buf);
		break;
	case KDBUS_CMD_MATCH_REMOVE:
		ret = kdbus_cmd_match_remove(conn, buf);
		break;
	case KDBUS_CMD_SEND:
		ret = kdbus_cmd_send(conn, file, buf);
		break;
	case KDBUS_CMD_RECV:
		ret = kdbus_cmd_recv(conn, buf);
		break;
	case KDBUS_CMD_FREE:
		ret = kdbus_cmd_free(conn, buf);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	kdbus_conn_release(release_conn);
	return ret;
}

/* kdbus endpoint commands for endpoint owners */
static long handle_ep_ioctl_owner(struct file *file, unsigned int command,
				  void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	struct kdbus_ep *ep = handle->ep_owner;
	int ret;

	switch (command) {
	case KDBUS_CMD_ENDPOINT_UPDATE:
		ret = kdbus_cmd_ep_update(ep, buf);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static long handle_ep_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct kdbus_handle_ep *handle = file->private_data;
	enum kdbus_handle_ep_type type;
	int ret = -EBADFD;

	/* While no type is set for this handle, we perform all ioctls locked.
	 * Once a type is fixed, it will never change again, so we only need
	 * the implicit memory-barrier provided by the mutex. */

	mutex_lock(&handle->lock);
	type = handle->type;
	if (type == KDBUS_HANDLE_EP_NONE)
		ret = handle_ep_ioctl_none(file, cmd, (void __user *)arg);
	mutex_unlock(&handle->lock);

	if (type == KDBUS_HANDLE_EP_CONNECTED)
		ret = handle_ep_ioctl_connected(file, cmd, (void __user *)arg);
	else if (type == KDBUS_HANDLE_EP_OWNER)
		ret = handle_ep_ioctl_owner(file, cmd, (void __user *)arg);

	return ret;
}

static unsigned int handle_ep_poll(struct file *file,
				   struct poll_table_struct *wait)
{
	struct kdbus_handle_ep *handle = file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;
	int ret;

	/* Only a connected endpoint can read/write data */
	mutex_lock(&handle->lock);
	if (handle->type != KDBUS_HANDLE_EP_CONNECTED) {
		mutex_unlock(&handle->lock);
		return POLLERR | POLLHUP;
	}
	mutex_unlock(&handle->lock);

	ret = kdbus_conn_acquire(handle->conn);
	if (ret < 0)
		return POLLERR | POLLHUP;

	poll_wait(file, &handle->conn->wait, wait);

	if (!list_empty(&handle->conn->queue.msg_list))
		mask |= POLLIN | POLLRDNORM;

	kdbus_conn_release(handle->conn);

	return mask;
}

static int handle_ep_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kdbus_handle_ep *handle = file->private_data;

	mutex_lock(&handle->lock);
	if (handle->type != KDBUS_HANDLE_EP_CONNECTED) {
		mutex_unlock(&handle->lock);
		return -EPERM;
	}
	mutex_unlock(&handle->lock);

	return kdbus_pool_mmap(handle->conn->pool, vma);
}

const struct file_operations kdbus_handle_ep_ops = {
	.owner =		THIS_MODULE,
	.open =			handle_ep_open,
	.release =		handle_ep_release,
	.poll =			handle_ep_poll,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	handle_ep_ioctl,
	.mmap =			handle_ep_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		handle_ep_ioctl,
#endif
};

static int handle_control_open(struct inode *inode, struct file *file)
{
	if (!kdbus_node_is_active(inode->i_private))
		return -ESHUTDOWN;

	/* private_data is used by BUS_MAKE to store the new bus */
	file->private_data = NULL;

	return 0;
}

static int handle_control_release(struct inode *inode, struct file *file)
{
	struct kdbus_bus *bus = file->private_data;

	if (bus) {
		kdbus_bus_deactivate(bus);
		kdbus_bus_unref(bus);
	}

	return 0;
}

static long handle_control_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct kdbus_node *node = file_inode(file)->i_private;
	struct kdbus_domain *domain;
	int ret = 0;

	/*
	 * The parent of control-nodes is always a domain, make sure to pin it
	 * so the parent is actually valid.
	 */
	if (!kdbus_node_acquire(node))
		return -ESHUTDOWN;

	domain = kdbus_domain_from_node(node->parent);
	if (!kdbus_node_acquire(&domain->node)) {
		kdbus_node_release(node);
		return -ESHUTDOWN;
	}

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE: {
		struct kdbus_bus *bus;

		/* catch double BUS_MAKE early, locked test is below */
		if (file->private_data) {
			ret = -EBADFD;
			break;
		}

		bus = kdbus_cmd_bus_make(domain, (void __user *)arg);
		if (IS_ERR(bus)) {
			ret = PTR_ERR(bus);
			break;
		}

		/* protect against parallel ioctls */
		mutex_lock(&domain->lock);
		if (file->private_data)
			ret = -EBADFD;
		else
			file->private_data = bus;
		mutex_unlock(&domain->lock);

		if (ret < 0) {
			kdbus_bus_deactivate(bus);
			kdbus_bus_unref(bus);
		}

		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kdbus_node_release(&domain->node);
	kdbus_node_release(node);
	return ret;
}

const struct file_operations kdbus_handle_control_ops = {
	.open =			handle_control_open,
	.release =		handle_control_release,
	.llseek =		noop_llseek,
	.unlocked_ioctl =	handle_control_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		handle_control_ioctl,
#endif
};
