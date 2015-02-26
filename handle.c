/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
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
#include <linux/poll.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "fs.h"
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

	if (args->cmd->flags & KDBUS_FLAG_NEGOTIATE) {
		if (put_user(args->allowed_flags & ~KDBUS_FLAG_NEGOTIATE,
			     &args->user->flags))
			return -EFAULT;
	}

	if (args->argc < 1 || args->argv[0].type != KDBUS_ITEM_NEGOTIATE ||
	    !args->argv[0].item)
		return 0;

	negotiation = args->argv[0].item;
	user = (struct kdbus_item __user *)
		((u8 __user *)args->user +
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

/**
 * __kdbus_args_parse() - parse payload of kdbus command
 * @args:		object to parse data into
 * @argp:		user-space location of command payload to parse
 * @type_size:		overall size of command payload to parse
 * @items_offset:	offset of items array in command payload
 * @out:		output variable to store pointer to copied payload
 *
 * This parses the ioctl payload at user-space location @argp into @args. @args
 * must be pre-initialized by the caller to reflect the supported flags and
 * items of this command. This parser will then copy the command payload into
 * kernel-space, verify correctness and consistency and cache pointers to parsed
 * items and other data in @args.
 *
 * If this function succeeded, you must call kdbus_args_clear() to release
 * allocated resources before destroying @args.
 *
 * Return: On failure a negative error code is returned. Otherwise, 1 is
 * returned if negotiation was requested, 0 if not.
 */
int __kdbus_args_parse(struct kdbus_args *args, void __user *argp,
		       size_t type_size, size_t items_offset, void **out)
{
	int ret;

	args->cmd = kdbus_memdup_user(argp, type_size, KDBUS_CMD_MAX_SIZE);
	if (IS_ERR(args->cmd))
		return PTR_ERR(args->cmd);

	args->cmd->return_flags = 0;
	args->user = argp;
	args->items = (void *)((u8 *)args->cmd + items_offset);
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
	return !!(args->cmd->flags & KDBUS_FLAG_NEGOTIATE);

error:
	return kdbus_args_clear(args, ret);
}

/**
 * kdbus_args_clear() - release allocated command resources
 * @args:	object to release resources of
 * @ret:	return value of this command
 *
 * This frees all allocated resources on @args and copies the command result
 * flags into user-space. @ret is usually returned unchanged by this function,
 * so it can be used in the final 'return' statement of the command handler.
 *
 * Return: -EFAULT if return values cannot be copied into user-space, otherwise
 *         @ret is returned unchanged.
 */
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
 * enum kdbus_handle_type - type an handle can be of
 * @KDBUS_HANDLE_NONE:		no type set, yet
 * @KDBUS_HANDLE_BUS_OWNER:	bus owner
 * @KDBUS_HANDLE_EP_OWNER:	endpoint owner
 * @KDBUS_HANDLE_CONNECTED:	endpoint connection after HELLO
 */
enum kdbus_handle_type {
	KDBUS_HANDLE_NONE,
	KDBUS_HANDLE_BUS_OWNER,
	KDBUS_HANDLE_EP_OWNER,
	KDBUS_HANDLE_CONNECTED,
};

/**
 * struct kdbus_handle - handle to the kdbus system
 * @rwlock:		handle lock
 * @type:		type of this handle (KDBUS_HANDLE_*)
 * @bus_owner:		bus this handle owns
 * @ep_owner:		endpoint this handle owns
 * @conn:		connection this handle owns
 * @privileged:		Flag to mark a handle as privileged
 */
struct kdbus_handle {
	struct rw_semaphore rwlock;

	enum kdbus_handle_type type;
	union {
		struct kdbus_bus *bus_owner;
		struct kdbus_ep *ep_owner;
		struct kdbus_conn *conn;
	};

	bool privileged:1;
};

static int kdbus_handle_open(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle;
	struct kdbus_node *node;
	int ret;

	node = kdbus_node_from_inode(inode);
	if (!kdbus_node_acquire(node))
		return -ESHUTDOWN;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle) {
		ret = -ENOMEM;
		goto exit;
	}

	init_rwsem(&handle->rwlock);
	handle->type = KDBUS_HANDLE_NONE;

	if (node->type == KDBUS_NODE_ENDPOINT) {
		struct kdbus_ep *ep = kdbus_ep_from_node(node);
		struct kdbus_bus *bus = ep->bus;

		/*
		 * A connection is privileged if it is opened on an endpoint
		 * without custom policy and either:
		 *   * the user has CAP_IPC_OWNER in the domain user namespace
		 * or
		 *   * the callers euid matches the uid of the bus creator
		 */
		if (!ep->user &&
		    (ns_capable(bus->domain->user_namespace, CAP_IPC_OWNER) ||
		     uid_eq(file->f_cred->euid, bus->node.uid)))
			handle->privileged = true;
	}

	file->private_data = handle;
	ret = 0;

exit:
	kdbus_node_release(node);
	return ret;
}

static int kdbus_handle_release(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle = file->private_data;

	switch (handle->type) {
	case KDBUS_HANDLE_BUS_OWNER:
		if (handle->bus_owner) {
			kdbus_node_deactivate(&handle->bus_owner->node);
			kdbus_bus_unref(handle->bus_owner);
		}
		break;
	case KDBUS_HANDLE_EP_OWNER:
		if (handle->ep_owner) {
			kdbus_node_deactivate(&handle->ep_owner->node);
			kdbus_ep_unref(handle->ep_owner);
		}
		break;
	case KDBUS_HANDLE_CONNECTED:
		kdbus_conn_disconnect(handle->conn, false);
		kdbus_conn_unref(handle->conn);
		break;
	case KDBUS_HANDLE_NONE:
		/* nothing to clean up */
		break;
	}

	kfree(handle);

	return 0;
}

static long kdbus_handle_ioctl_control(struct file *file, unsigned int cmd,
				       void __user *argp)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_node *node = file_inode(file)->i_private;
	struct kdbus_domain *domain;
	int ret = 0;

	if (!kdbus_node_acquire(node))
		return -ESHUTDOWN;

	/*
	 * The parent of control-nodes is always a domain, make sure to pin it
	 * so the parent is actually valid.
	 */
	domain = kdbus_domain_from_node(node->parent);
	if (!kdbus_node_acquire(&domain->node)) {
		kdbus_node_release(node);
		return -ESHUTDOWN;
	}

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE: {
		struct kdbus_bus *bus;

		bus = kdbus_cmd_bus_make(domain, argp);
		if (IS_ERR_OR_NULL(bus)) {
			ret = PTR_ERR_OR_ZERO(bus);
			break;
		}

		handle->type = KDBUS_HANDLE_BUS_OWNER;
		handle->bus_owner = bus;
		break;
	}

	default:
		ret = -EBADFD;
		break;
	}

	kdbus_node_release(&domain->node);
	kdbus_node_release(node);
	return ret;
}

static long kdbus_handle_ioctl_ep(struct file *file, unsigned int cmd,
				  void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_node *node = file_inode(file)->i_private;
	struct kdbus_ep *ep, *file_ep = kdbus_ep_from_node(node);
	struct kdbus_conn *conn;
	int ret = 0;

	if (!kdbus_node_acquire(node))
		return -ESHUTDOWN;

	switch (cmd) {
	case KDBUS_CMD_ENDPOINT_MAKE:
		/* creating custom endpoints is a privileged operation */
		if (!handle->privileged) {
			ret = -EPERM;
			break;
		}

		ep = kdbus_cmd_ep_make(file_ep->bus, buf);
		if (IS_ERR_OR_NULL(ep)) {
			ret = PTR_ERR_OR_ZERO(ep);
			break;
		}

		handle->type = KDBUS_HANDLE_EP_OWNER;
		handle->ep_owner = ep;
		break;

	case KDBUS_CMD_HELLO:
		conn = kdbus_cmd_hello(file_ep, handle->privileged, buf);
		if (IS_ERR_OR_NULL(conn)) {
			ret = PTR_ERR_OR_ZERO(conn);
			break;
		}

		handle->type = KDBUS_HANDLE_CONNECTED;
		handle->conn = conn;
		break;

	default:
		ret = -EBADFD;
		break;
	}

	kdbus_node_release(node);
	return ret;
}

static long kdbus_handle_ioctl_ep_owner(struct file *file, unsigned int command,
					void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_ep *ep = handle->ep_owner;
	int ret;

	if (!kdbus_node_acquire(&ep->node))
		return -ESHUTDOWN;

	switch (command) {
	case KDBUS_CMD_ENDPOINT_UPDATE:
		ret = kdbus_cmd_ep_update(ep, buf);
		break;
	default:
		ret = -EBADFD;
		break;
	}

	kdbus_node_release(&ep->node);
	return ret;
}

static long kdbus_handle_ioctl_connected(struct file *file,
					 unsigned int command, void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
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
		ret = -EBADFD;
		break;
	}

	kdbus_conn_release(release_conn);
	return ret;
}

static long kdbus_handle_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_node *node = kdbus_node_from_inode(file_inode(file));
	void __user *argp = (void __user *)arg;
	long ret = -EBADFD;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE:
	case KDBUS_CMD_ENDPOINT_MAKE:
	case KDBUS_CMD_HELLO:
		/* bail out early if already typed */
		if (handle->type != KDBUS_HANDLE_NONE)
			break;

		down_write(&handle->rwlock);
		if (handle->type == KDBUS_HANDLE_NONE) {
			if (node->type == KDBUS_NODE_CONTROL)
				ret = kdbus_handle_ioctl_control(file, cmd,
								 argp);
			else if (node->type == KDBUS_NODE_ENDPOINT)
				ret = kdbus_handle_ioctl_ep(file, cmd, argp);
		}
		up_write(&handle->rwlock);
		break;

	case KDBUS_CMD_ENDPOINT_UPDATE:
	case KDBUS_CMD_BYEBYE:
	case KDBUS_CMD_NAME_ACQUIRE:
	case KDBUS_CMD_NAME_RELEASE:
	case KDBUS_CMD_LIST:
	case KDBUS_CMD_CONN_INFO:
	case KDBUS_CMD_BUS_CREATOR_INFO:
	case KDBUS_CMD_UPDATE:
	case KDBUS_CMD_MATCH_ADD:
	case KDBUS_CMD_MATCH_REMOVE:
	case KDBUS_CMD_SEND:
	case KDBUS_CMD_RECV:
	case KDBUS_CMD_FREE:
		down_read(&handle->rwlock);
		if (handle->type == KDBUS_HANDLE_EP_OWNER)
			ret = kdbus_handle_ioctl_ep_owner(file, cmd, argp);
		else if (handle->type == KDBUS_HANDLE_CONNECTED)
			ret = kdbus_handle_ioctl_connected(file, cmd, argp);
		up_read(&handle->rwlock);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret < 0 ? ret : 0;
}

static unsigned int kdbus_handle_poll(struct file *file,
				      struct poll_table_struct *wait)
{
	struct kdbus_handle *handle = file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;
	int ret;

	/* Only a connected endpoint can read/write data */
	down_read(&handle->rwlock);
	if (handle->type != KDBUS_HANDLE_CONNECTED) {
		up_read(&handle->rwlock);
		return POLLERR | POLLHUP;
	}
	up_read(&handle->rwlock);

	ret = kdbus_conn_acquire(handle->conn);
	if (ret < 0)
		return POLLERR | POLLHUP;

	poll_wait(file, &handle->conn->wait, wait);

	if (!list_empty(&handle->conn->queue.msg_list) ||
	    atomic_read(&handle->conn->lost_count) > 0)
		mask |= POLLIN | POLLRDNORM;

	kdbus_conn_release(handle->conn);

	return mask;
}

static int kdbus_handle_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kdbus_handle *handle = file->private_data;
	int ret = -EBADFD;

	if (down_read_trylock(&handle->rwlock)) {
		if (handle->type == KDBUS_HANDLE_CONNECTED)
			ret = kdbus_pool_mmap(handle->conn->pool, vma);
		up_read(&handle->rwlock);
	}
	return ret;
}

const struct file_operations kdbus_handle_ops = {
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
