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

static void *__kdbus_enter_cmd(void __user *ucmd, size_t cmd_size,
			       size_t off_items, u64 cmd_allowed_flags,
			       bool cmd_has_items) {
	struct kdbus_cmd __user *ucmdt = ucmd;
	struct kdbus_item *items, *item;
	struct kdbus_cmd *cmd = NULL;
	int ret;

	WARN_ON_ONCE(cmd_allowed_flags & KDBUS_FLAG_KERNEL);

	cmd = kdbus_memdup_user(ucmd, cmd_size, KDBUS_CMD_MAX_SIZE);
	if (IS_ERR(cmd))
		return ERR_CAST(cmd);

	items = (void*)((u8 *)cmd + off_items);
	cmd->kernel_flags = cmd_allowed_flags | KDBUS_FLAG_KERNEL;
	cmd->return_flags = 0;

	if (put_user(cmd->kernel_flags, &ucmdt->kernel_flags)) {
		ret = -EFAULT;
		goto error;
	}

	if (cmd->flags & ~cmd_allowed_flags) {
		ret = -EINVAL;
		goto error;
	}

	ret = kdbus_items_validate(items, cmd->size - off_items);
	if (ret < 0)
		goto error;

	if (!cmd_has_items) {
		KDBUS_ITEMS_FOREACH(item, items, cmd->size - off_items) {
			ret = -EINVAL;
			goto error;
		}
	}

	return cmd;

error:
	kfree(cmd);
	return ERR_PTR(ret);
}

#define kdbus_enter_cmd(_ucmd, _cmd_type, _cmd_flags, _cmd_has_items)   \
	({                                                              \
		BUILD_BUG_ON(offsetof(_cmd_type, size) !=               \
			     offsetof(struct kdbus_cmd, size));         \
		BUILD_BUG_ON(offsetof(_cmd_type, flags) !=              \
			     offsetof(struct kdbus_cmd, flags));        \
		BUILD_BUG_ON(offsetof(_cmd_type, kernel_flags) !=       \
			     offsetof(struct kdbus_cmd, kernel_flags)); \
		BUILD_BUG_ON(offsetof(_cmd_type, return_flags) !=       \
			     offsetof(struct kdbus_cmd, return_flags)); \
		__kdbus_enter_cmd((_ucmd), sizeof(_cmd_type),           \
				  offsetof(_cmd_type, items),           \
				  (_cmd_flags), (_cmd_has_items));      \
	})

static int kdbus_leave_cmd(void __user *ucmd, void *cmd, int ret) {
	struct kdbus_cmd __user *ucmdt = ucmd;
	struct kdbus_cmd *cmdt = cmd;

	if (IS_ERR_OR_NULL(cmd))
		return ret;

	if (put_user(cmdt->return_flags, &ucmdt->return_flags))
		ret = -EFAULT;

	kfree(cmd);
	return ret;
}

static int handle_ep_ioctl_endpoint_make(struct kdbus_handle_ep *handle,
					 void __user *buf)
{
	struct kdbus_cmd *cmd;
	struct kdbus_ep *ep = NULL;
	const char *name;
	int ret;

	lockdep_assert_held(&handle->lock);
	if (WARN_ON(handle->type != KDBUS_HANDLE_EP_NONE))
		return -EBADFD;

	/* creating custom endpoints is a privileged operation */
	if (!handle->privileged)
		return -EPERM;

	cmd = kdbus_enter_cmd(buf, struct kdbus_cmd,
			      KDBUS_MAKE_ACCESS_GROUP |
			      KDBUS_MAKE_ACCESS_WORLD, true);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	name = kdbus_items_get_str(cmd->items, KDBUS_ITEMS_SIZE(cmd, items),
				   KDBUS_ITEM_MAKE_NAME);
	if (IS_ERR(name)) {
		ret = PTR_ERR(name);
		goto exit;
	}

	ep = kdbus_ep_new(handle->ep->bus, name,
			  cmd->flags & (KDBUS_MAKE_ACCESS_WORLD |
			                KDBUS_MAKE_ACCESS_GROUP),
			  current_euid(), current_egid(), true);
	if (IS_ERR(ep)) {
		ret = PTR_ERR(ep);
		ep = NULL;
		goto exit;
	}

	ret = kdbus_ep_activate(ep);
	if (ret < 0)
		goto exit;

	ret = kdbus_ep_policy_set(ep, cmd->items, KDBUS_ITEMS_SIZE(cmd, items));
	if (ret < 0)
		goto exit;

	/* protect against parallel ioctls */
	handle->type = KDBUS_HANDLE_EP_OWNER;
	handle->ep_owner = ep;

exit:
	if (ret < 0) {
		kdbus_ep_deactivate(ep);
		kdbus_ep_unref(ep);
	}
	return kdbus_leave_cmd(buf, cmd, ret);
}

static int handle_ep_ioctl_hello(struct kdbus_handle_ep *handle,
				 void __user *buf)
{
	struct kdbus_conn *conn = NULL;
	struct kdbus_cmd_hello *hello;
	int ret;

	lockdep_assert_held(&handle->lock);
	if (WARN_ON(handle->type != KDBUS_HANDLE_EP_NONE))
		return -EBADFD;

	hello = kdbus_enter_cmd(buf, struct kdbus_cmd_hello,
				KDBUS_HELLO_ACCEPT_FD |
				KDBUS_HELLO_ACTIVATOR |
				KDBUS_HELLO_POLICY_HOLDER |
				KDBUS_HELLO_MONITOR, true);
	if (IS_ERR(hello))
		return PTR_ERR(hello);

	if (!hello->pool_size || !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
		ret = -EFAULT;
		goto exit;
	}

	conn = kdbus_conn_new(handle->ep, hello, handle->privileged);
	if (IS_ERR(conn)) {
		ret = PTR_ERR(conn);
		conn = NULL;
		goto exit;
	}

	ret = kdbus_conn_connect(conn, hello);
	if (ret < 0)
		goto exit;

	if (kdbus_conn_is_activator(conn) ||
	    kdbus_conn_is_policy_holder(conn)) {
		ret = kdbus_conn_acquire(conn);
		if (ret < 0)
			goto exit;

		ret = kdbus_policy_set(&conn->ep->bus->policy_db, hello->items,
				       KDBUS_ITEMS_SIZE(hello, items),
				       1, kdbus_conn_is_policy_holder(conn),
				       conn);
		kdbus_conn_release(conn);
		if (ret < 0)
			goto exit;
	}

	if (copy_to_user(buf, hello, sizeof(*hello))) {
		ret = -EFAULT;
		goto exit;
	}

	/* protect against parallel ioctls */
	handle->type = KDBUS_HANDLE_EP_CONNECTED;
	handle->conn = conn;

exit:
	if (ret < 0 && conn) {
		kdbus_conn_disconnect(conn, false);
		kdbus_conn_unref(conn);
	}
	return kdbus_leave_cmd(buf, hello, ret);
}

/* kdbus endpoint make commands */
static long handle_ep_ioctl_none(struct file *file, unsigned int cmd,
				 void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	long ret;

	switch (cmd) {
	case KDBUS_CMD_ENDPOINT_MAKE:
		ret = handle_ep_ioctl_endpoint_make(handle, buf);
		break;

	case KDBUS_CMD_HELLO:
		ret = handle_ep_ioctl_hello(handle, buf);
		break;

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
	void *cmd = NULL;
	int ret = 0;

	ret = kdbus_conn_acquire(conn);
	if (ret < 0)
		return ret;

	release_conn = conn;

	switch (command) {
	case KDBUS_CMD_BYEBYE: {
		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd, 0, false);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		/*
		 * BYEBYE is special; we must not acquire a connection when
		 * calling into kdbus_conn_disconnect() or we will deadlock,
		 * because kdbus_conn_disconnect() will wait for all acquired
		 * references to be dropped.
		 */
		kdbus_conn_release(release_conn);
		release_conn = NULL;

		ret = kdbus_conn_disconnect(conn, true);
		break;
	}

	case KDBUS_CMD_NAME_ACQUIRE: {
		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd,
				      KDBUS_NAME_REPLACE_EXISTING |
				      KDBUS_NAME_ALLOW_REPLACEMENT |
				      KDBUS_NAME_QUEUE, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		ret = kdbus_cmd_name_acquire(conn->ep->bus->name_registry,
					     conn, cmd);
		if (ret < 0)
			break;

		if (copy_to_user(buf, cmd, ((struct kdbus_cmd*)cmd)->size))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_NAME_RELEASE: {
		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd, 0, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		ret = kdbus_cmd_name_release(conn->ep->bus->name_registry,
					     conn, cmd);
		break;
	}

	case KDBUS_CMD_NAME_LIST: {
		struct kdbus_cmd_name_list *cmd_list;

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_name_list,
				      KDBUS_NAME_LIST_UNIQUE |
				      KDBUS_NAME_LIST_NAMES |
				      KDBUS_NAME_LIST_ACTIVATORS |
				      KDBUS_NAME_LIST_QUEUED, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}
		cmd_list = cmd;

		ret = kdbus_cmd_name_list(conn->ep->bus->name_registry,
					  conn, cmd_list);
		if (ret < 0)
			break;

		if (kdbus_member_set_user(&cmd_list->offset, buf,
					  struct kdbus_cmd_name_list, offset) ||
		    kdbus_member_set_user(&cmd_list->list_size, buf,
					  struct kdbus_cmd_name_list,
					  list_size))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_INFO:
	case KDBUS_CMD_BUS_CREATOR_INFO: {
		struct kdbus_cmd_info *cmd_info;

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_info,
				      _KDBUS_ATTACH_ALL, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}
		cmd_info = cmd;

		if (command == KDBUS_CMD_CONN_INFO)
			ret = kdbus_cmd_conn_info(conn, cmd_info);
		else
			ret = kdbus_cmd_bus_creator_info(conn, cmd_info);

		if (ret < 0)
			break;

		if (kdbus_member_set_user(&cmd_info->offset, buf,
					  struct kdbus_cmd_info, offset) ||
		    kdbus_member_set_user(&cmd_info->info_size, buf,
					  struct kdbus_cmd_info, info_size))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_UPDATE: {
		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_policy_holder(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd, 0, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		ret = kdbus_cmd_conn_update(conn, cmd);
		break;
	}

	case KDBUS_CMD_MATCH_ADD: {
		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_match,
				      KDBUS_MATCH_REPLACE, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		ret = kdbus_match_db_add(conn, cmd);
		if (ret < 0)
			break;

		break;
	}

	case KDBUS_CMD_MATCH_REMOVE: {
		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_match, 0, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		ret = kdbus_match_db_remove(conn, cmd);
		break;
	}

	case KDBUS_CMD_SEND: {
		struct kdbus_cmd_send *cmd_send;
		struct kdbus_kmsg *kmsg = NULL;

		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_send,
				      KDBUS_SEND_SYNC_REPLY, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		cmd_send = cmd;
		cmd_send->reply.offset = 0;
		cmd_send->reply.msg_size = 0;
		cmd_send->reply.return_flags = 0;

		kmsg = kdbus_kmsg_new_from_cmd(conn, buf, cmd_send);
		if (IS_ERR(kmsg)) {
			ret = PTR_ERR(kmsg);
			break;
		}

		ret = kdbus_cmd_msg_send(conn, cmd_send, file, kmsg);
		if (ret >= 0) {
			if (kdbus_member_set_user(&cmd_send->reply, buf,
						  struct kdbus_cmd_send,
						  reply))
				ret = -EFAULT;
		}

		kdbus_kmsg_free(kmsg);
		break;
	}

	case KDBUS_CMD_RECV: {
		struct kdbus_cmd_recv *cmd_recv;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn) &&
		    !kdbus_conn_is_activator(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_recv,
				      KDBUS_RECV_PEEK |
				      KDBUS_RECV_DROP |
				      KDBUS_RECV_USE_PRIORITY, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		cmd_recv = cmd;
		cmd_recv->dropped_msgs = 0;
		cmd_recv->msg.offset = 0;
		cmd_recv->msg.msg_size = 0;
		cmd_recv->msg.return_flags = 0;

		ret = kdbus_cmd_msg_recv(conn, cmd_recv);

		if (kdbus_member_set_user(&cmd_recv->dropped_msgs, buf,
					  struct kdbus_cmd_recv,
					  dropped_msgs) ||
		    kdbus_member_set_user(&cmd_recv->msg, buf,
					  struct kdbus_cmd_recv, msg))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_FREE: {
		struct kdbus_cmd_free *cmd_free;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn) &&
		    !kdbus_conn_is_activator(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd_free, 0, false);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}
		cmd_free = cmd;

		ret = kdbus_pool_release_offset(conn->pool, cmd_free->offset);
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kdbus_conn_release(release_conn);
	return kdbus_leave_cmd(buf, cmd, ret);
}

/* kdbus endpoint commands for endpoint owners */
static long handle_ep_ioctl_owner(struct file *file, unsigned int command,
				  void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	struct kdbus_ep *ep = handle->ep_owner;
	void *cmd = NULL;
	long ret = 0;

	switch (command) {
	case KDBUS_CMD_ENDPOINT_UPDATE: {
		struct kdbus_cmd *cmd_update;

		cmd = kdbus_enter_cmd(buf, struct kdbus_cmd, 0, true);
		if (IS_ERR(cmd)) {
			ret = PTR_ERR(cmd);
			break;
		}

		cmd_update = cmd;
		ret = kdbus_ep_policy_set(ep, cmd_update->items,
					  KDBUS_ITEMS_SIZE(cmd_update, items));
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	return kdbus_leave_cmd(buf, cmd, ret);
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

static int handle_control_ioctl_bus_make(struct file *file,
					 struct kdbus_domain *domain,
					 void __user *buf)
{
	struct kdbus_cmd *cmd;
	struct kdbus_bus *bus = NULL;
	int ret;

	/* catch double BUS_MAKE early, locked test is below */
	if (file->private_data)
		return -EBADFD;

	cmd = kdbus_enter_cmd(buf, struct kdbus_cmd,
			      KDBUS_MAKE_ACCESS_GROUP |
			      KDBUS_MAKE_ACCESS_WORLD, true);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	bus = kdbus_bus_new(domain, cmd, current_euid(), current_egid());
	if (IS_ERR(bus)) {
		ret = PTR_ERR(bus);
		bus = NULL;
		goto exit;
	}

	ret = kdbus_bus_activate(bus);
	if (ret < 0)
		goto exit;

	/* protect against parallel ioctls */
	mutex_lock(&domain->lock);
	if (file->private_data)
		ret = -EBADFD;
	else
		file->private_data = bus;
	mutex_unlock(&domain->lock);

exit:
	if (ret < 0) {
		kdbus_bus_deactivate(bus);
		kdbus_bus_unref(bus);
	}
	return kdbus_leave_cmd(buf, cmd, ret);
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
	case KDBUS_CMD_BUS_MAKE:
		ret = handle_control_ioctl_bus_make(file, domain,
						    (void __user *)arg);
		break;

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
