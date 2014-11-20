/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
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
#include "metadata.h"
#include "names.h"
#include "domain.h"
#include "policy.h"

/**
 * enum kdbus_handle_ep_type - type an endpoint handle can be of
 * @KDBUS_HANDLE_EP_NONE:	New file descriptor on an endpoint
 * @KDBUS_HANDLE_EP_CONNECTED:	A bus connection after HELLO
 * @KDBUS_HANDLE_EP_OWNER:	File descriptor to hold an endpoint
 */
enum kdbus_handle_ep_type {
	KDBUS_HANDLE_EP_NONE,
	KDBUS_HANDLE_EP_CONNECTED,
	KDBUS_HANDLE_EP_OWNER,
};

/**
 * struct handle_ep - an endpoint handle to the kdbus system
 * @lock:		Handle lock
 * @meta:		Cached connection creator's metadata/credentials
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
	struct kdbus_meta *meta;
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
	struct kdbus_node *node;
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

	if (ns_capable(&init_user_ns, CAP_IPC_OWNER) ||
	    uid_eq(handle->ep->bus->node.uid, file->f_cred->fsuid))
		handle->privileged = true;

	/* cache the metadata/credentials of the creator */
	handle->meta = kdbus_meta_new();
	if (IS_ERR(handle->meta)) {
		ret = PTR_ERR(handle->meta);
		goto exit_free;
	}

	ret = kdbus_meta_append(handle->meta, handle->ep->bus->domain, NULL, 0,
				KDBUS_ATTACH_CREDS	|
				KDBUS_ATTACH_AUXGROUPS	|
				KDBUS_ATTACH_TID_COMM	|
				KDBUS_ATTACH_PID_COMM	|
				KDBUS_ATTACH_EXE	|
				KDBUS_ATTACH_CMDLINE	|
				KDBUS_ATTACH_CGROUP	|
				KDBUS_ATTACH_CAPS	|
				KDBUS_ATTACH_SECLABEL	|
				KDBUS_ATTACH_AUDIT);
	if (ret < 0)
		goto exit_free;

	file->private_data = handle;
	kdbus_node_release(node);

	return 0;

exit_free:
	kdbus_meta_free(handle->meta);
	kdbus_ep_unref(handle->ep);
	kfree(handle);
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

	kdbus_meta_free(handle->meta);
	kdbus_ep_unref(handle->ep);
	kfree(handle);

	return 0;
}

static int handle_ep_ioctl_endpoint_make(struct kdbus_handle_ep *handle,
					 void __user *buf)
{
	struct kdbus_domain_user *user;
	struct kdbus_cmd_make *make;
	struct kdbus_ep *ep;
	unsigned int access;
	const char *name;
	int ret;

	/* creating custom endpoints is a privileged operation */
	if (!handle->privileged)
		return -EPERM;

	make = kdbus_memdup_user(buf, sizeof(*make), KDBUS_MAKE_MAX_SIZE);
	if (IS_ERR(make))
		return PTR_ERR(make);

	ret = kdbus_negotiate_flags(make, buf, struct kdbus_cmd_make,
				    KDBUS_MAKE_ACCESS_GROUP |
				    KDBUS_MAKE_ACCESS_WORLD);
	if (ret < 0)
		goto exit;

	ret = kdbus_items_validate(make->items, KDBUS_ITEMS_SIZE(make, items));
	if (ret < 0)
		goto exit;

	name = kdbus_items_get_str(make->items, KDBUS_ITEMS_SIZE(make, items),
				   KDBUS_ITEM_MAKE_NAME);
	if (IS_ERR(name)) {
		ret = PTR_ERR(name);
		goto exit;
	}

	access = make->flags & (KDBUS_MAKE_ACCESS_WORLD |
				KDBUS_MAKE_ACCESS_GROUP);

	ep = kdbus_ep_new(handle->ep->bus, name, access, current_fsuid(),
			  current_fsgid(), true);
	if (IS_ERR(ep)) {
		ret = PTR_ERR(ep);
		goto exit;
	}

	/*
	 * Get an anonymous user to account messages against; custom
	 * endpoint users do not share the budget with the ordinary
	 * users created for a UID.
	 */
	user = kdbus_domain_get_user(handle->ep->bus->domain, INVALID_UID);
	if (IS_ERR(user)) {
		ret = PTR_ERR(user);
		goto exit_ep_unref;
	}
	ep->user = user;

	ret = kdbus_ep_activate(ep);
	if (ret < 0)
		goto exit_ep_unref;

	ret = kdbus_ep_policy_set(ep, make->items,
				  KDBUS_ITEMS_SIZE(make, items));
	if (ret < 0)
		goto exit_ep_unref;

	/* protect against parallel ioctls */
	mutex_lock(&handle->lock);
	if (handle->type != KDBUS_HANDLE_EP_NONE) {
		ret = -EBADFD;
	} else {
		handle->type = KDBUS_HANDLE_EP_OWNER;
		handle->ep_owner = ep;
	}
	mutex_unlock(&handle->lock);

	if (ret < 0)
		goto exit_ep_unref;

	goto exit;

exit_ep_unref:
	kdbus_ep_deactivate(ep);
	kdbus_ep_unref(ep);
exit:
	kfree(make);
	return ret;
}

static int handle_ep_ioctl_hello(struct kdbus_handle_ep *handle,
				 void __user *buf)
{
	struct kdbus_conn *conn;
	struct kdbus_cmd_hello *hello;
	int ret;

	hello = kdbus_memdup_user(buf, sizeof(*hello), KDBUS_HELLO_MAX_SIZE);
	if (IS_ERR(hello))
		return PTR_ERR(hello);

	ret = kdbus_negotiate_flags(hello, buf, typeof(*hello),
				    KDBUS_HELLO_ACCEPT_FD |
				    KDBUS_HELLO_ACTIVATOR |
				    KDBUS_HELLO_POLICY_HOLDER |
				    KDBUS_HELLO_MONITOR);
	if (ret < 0)
		goto exit;

	ret = kdbus_items_validate(hello->items,
				   KDBUS_ITEMS_SIZE(hello, items));
	if (ret < 0)
		goto exit;

	if (!hello->pool_size || !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
		ret = -EFAULT;
		goto exit;
	}

	conn = kdbus_conn_new(handle->ep, hello, handle->meta,
			      handle->privileged);
	if (IS_ERR(conn)) {
		ret = PTR_ERR(conn);
		goto exit;
	}

	if (copy_to_user(buf, hello, sizeof(*hello))) {
		ret = -EFAULT;
		goto exit_conn_live;
	}

	/* protect against parallel ioctls */
	mutex_lock(&handle->lock);
	if (handle->type != KDBUS_HANDLE_EP_NONE) {
		ret = -EBADFD;
	} else {
		handle->type = KDBUS_HANDLE_EP_CONNECTED;
		handle->conn = conn;
	}
	mutex_unlock(&handle->lock);

	if (ret < 0)
		goto exit_conn_live;

	goto exit;

exit_conn_live:
	kdbus_conn_disconnect(conn, false);
	kdbus_conn_unref(conn);
exit:
	kfree(hello);
	return ret;
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

	case KDBUS_CMD_HELLO: {
		ret = handle_ep_ioctl_hello(handle, buf);
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

/* kdbus endpoint commands for connected peers */
static long handle_ep_ioctl_connected(struct file *file, unsigned int cmd,
				      void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	struct kdbus_conn *conn = handle->conn;
	void *free_ptr = NULL;
	long ret = 0;

	/*
	 * BYEBYE is special; we must not acquire a connection when
	 * calling into kdbus_conn_disconnect() or we will deadlock,
	 * because kdbus_conn_disconnect() will wait for all acquired
	 * references to be dropped.
	 */
	if (cmd == KDBUS_CMD_BYEBYE) {
		if (!kdbus_conn_is_ordinary(conn))
			return -EOPNOTSUPP;

		return kdbus_conn_disconnect(conn, true);
	}

	ret = kdbus_conn_acquire(conn);
	if (ret < 0)
		return ret;

	switch (cmd) {
	case KDBUS_CMD_NAME_ACQUIRE: {
		/* acquire a well-known name */
		struct kdbus_cmd_name *cmd_name;

		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd_name = kdbus_memdup_user(buf, sizeof(*cmd_name),
					     sizeof(*cmd_name) +
						KDBUS_ITEM_HEADER_SIZE +
						KDBUS_NAME_MAX_LEN + 1);
		if (IS_ERR(cmd_name)) {
			ret = PTR_ERR(cmd_name);
			break;
		}

		free_ptr = cmd_name;

		ret = kdbus_negotiate_flags(cmd_name, buf, typeof(*cmd_name),
					    KDBUS_NAME_REPLACE_EXISTING |
					    KDBUS_NAME_ALLOW_REPLACEMENT |
					    KDBUS_NAME_QUEUE);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_name->items,
					   KDBUS_ITEMS_SIZE(cmd_name, items));
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_acquire(conn->ep->bus->name_registry,
					     conn, cmd_name);
		if (ret < 0)
			break;

		/* return flags to the caller */
		if (copy_to_user(buf, cmd_name, cmd_name->size))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_NAME_RELEASE: {
		/* release a well-known name */
		struct kdbus_cmd_name *cmd_name;

		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd_name = kdbus_memdup_user(buf, sizeof(*cmd_name),
					     sizeof(*cmd_name) +
						KDBUS_ITEM_HEADER_SIZE +
						KDBUS_NAME_MAX_LEN + 1);
		if (IS_ERR(cmd_name)) {
			ret = PTR_ERR(cmd_name);
			break;
		}

		free_ptr = cmd_name;

		ret = kdbus_negotiate_flags(cmd_name, buf, typeof(*cmd_name),
					    0);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_name->items,
					   KDBUS_ITEMS_SIZE(cmd_name, items));
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_release(conn->ep->bus->name_registry,
					     conn, cmd_name);
		break;
	}

	case KDBUS_CMD_NAME_LIST: {
		struct kdbus_cmd_name_list cmd_list;

		/* query current IDs and names */
		if (kdbus_copy_from_user(&cmd_list, buf, sizeof(cmd_list))) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_negotiate_flags(&cmd_list, buf, typeof(cmd_list),
					    KDBUS_NAME_LIST_UNIQUE |
					    KDBUS_NAME_LIST_NAMES |
					    KDBUS_NAME_LIST_ACTIVATORS |
					    KDBUS_NAME_LIST_QUEUED);
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_list(conn->ep->bus->name_registry,
					  conn, &cmd_list);
		if (ret < 0)
			break;

		/* return allocated data */
		if (kdbus_offset_set_user(&cmd_list.offset, buf,
					  struct kdbus_cmd_name_list))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_INFO:
	case KDBUS_CMD_BUS_CREATOR_INFO: {
		struct kdbus_cmd_info *cmd_info;

		/* return the properties of a connection */
		cmd_info = kdbus_memdup_user(buf, sizeof(*cmd_info),
					     sizeof(*cmd_info) +
						KDBUS_NAME_MAX_LEN + 1);
		if (IS_ERR(cmd_info)) {
			ret = PTR_ERR(cmd_info);
			break;
		}

		free_ptr = cmd_info;

		ret = kdbus_negotiate_flags(cmd_info, buf, typeof(*cmd_info),
					    _KDBUS_ATTACH_ALL);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_info->items,
					   KDBUS_ITEMS_SIZE(cmd_info, items));
		if (ret < 0)
			break;

		if (cmd == KDBUS_CMD_CONN_INFO)
			ret = kdbus_cmd_info(conn, cmd_info);
		else
			ret = kdbus_cmd_bus_creator_info(conn, cmd_info);

		if (ret < 0)
			break;

		if (kdbus_offset_set_user(&cmd_info->offset, buf,
					  struct kdbus_cmd_info))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_UPDATE: {
		/* update the properties of a connection */
		struct kdbus_cmd_update *cmd_update;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_policy_holder(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd_update = kdbus_memdup_user(buf, sizeof(*cmd_update),
					       KDBUS_UPDATE_MAX_SIZE);
		if (IS_ERR(cmd_update)) {
			ret = PTR_ERR(cmd_update);
			break;
		}

		free_ptr = cmd_update;

		ret = kdbus_negotiate_flags(cmd_update, buf,
					    typeof(*cmd_update), 0);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_update->items,
					   KDBUS_ITEMS_SIZE(cmd_update, items));
		if (ret < 0)
			break;

		ret = kdbus_cmd_conn_update(conn, cmd_update);
		break;
	}

	case KDBUS_CMD_MATCH_ADD: {
		/* subscribe to/filter for broadcast messages */
		struct kdbus_cmd_match *cmd_match;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd_match = kdbus_memdup_user(buf, sizeof(*cmd_match),
					      KDBUS_MATCH_MAX_SIZE);
		if (IS_ERR(cmd_match)) {
			ret = PTR_ERR(cmd_match);
			break;
		}

		free_ptr = cmd_match;

		ret = kdbus_negotiate_flags(cmd_match, buf, typeof(*cmd_match),
					    KDBUS_MATCH_REPLACE);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_match->items,
					   KDBUS_ITEMS_SIZE(cmd_match, items));
		if (ret < 0)
			break;

		ret = kdbus_match_db_add(conn, cmd_match);
		break;
	}

	case KDBUS_CMD_MATCH_REMOVE: {
		/* unsubscribe from broadcast messages */
		struct kdbus_cmd_match *cmd_match;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		cmd_match = kdbus_memdup_user(buf, sizeof(*cmd_match),
					      sizeof(*cmd_match));
		if (IS_ERR(cmd_match)) {
			ret = PTR_ERR(cmd_match);
			break;
		}

		free_ptr = cmd_match;

		ret = kdbus_negotiate_flags(cmd_match, buf, typeof(*cmd_match),
					    0);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_match->items,
					   KDBUS_ITEMS_SIZE(cmd_match, items));
		if (ret < 0)
			break;

		ret = kdbus_match_db_remove(conn, cmd_match);
		break;
	}

	case KDBUS_CMD_MSG_SEND: {
		/* submit a message which will be queued in the receiver */
		struct kdbus_kmsg *kmsg = NULL;

		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		kmsg = kdbus_kmsg_new_from_user(conn, buf);
		if (IS_ERR(kmsg)) {
			ret = PTR_ERR(kmsg);
			break;
		}

		ret = kdbus_conn_kmsg_send(conn->ep, conn, kmsg);
		if (ret < 0) {
			kdbus_kmsg_free(kmsg);
			break;
		}

		/* store the offset of the reply back to userspace */
		if (kmsg->msg.flags & KDBUS_MSG_FLAGS_SYNC_REPLY) {
			struct kdbus_msg __user *msg = buf;

			if (copy_to_user(&msg->offset_reply,
					 &kmsg->msg.offset_reply,
					 sizeof(msg->offset_reply)))
				ret = -EFAULT;
		}

		kdbus_kmsg_free(kmsg);
		break;
	}

	case KDBUS_CMD_MSG_RECV: {
		struct kdbus_cmd_recv cmd_recv;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_copy_from_user(&cmd_recv, buf, sizeof(cmd_recv));
		if (ret < 0)
			break;

		ret = kdbus_negotiate_flags(&cmd_recv, buf, typeof(cmd_recv),
					    KDBUS_RECV_PEEK | KDBUS_RECV_DROP |
					    KDBUS_RECV_USE_PRIORITY);
		if (ret < 0)
			break;

		ret = kdbus_cmd_msg_recv(conn, &cmd_recv);
		if (ret < 0)
			break;

		/* return the address of the next message in the pool */
		if (kdbus_offset_set_user(&cmd_recv.offset, buf,
					  struct kdbus_cmd_recv))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_MSG_CANCEL: {
		struct kdbus_cmd_cancel cmd_cancel;

		if (!kdbus_conn_is_ordinary(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		/* cancel sync message send requests by cookie */
		ret = kdbus_copy_from_user(&cmd_cancel, buf,
					   sizeof(cmd_cancel));
		if (ret < 0)
			break;

		if (cmd_cancel.flags != 0)
			return -EOPNOTSUPP;

		ret = kdbus_cmd_msg_cancel(conn, cmd_cancel.cookie);
		break;
	}

	case KDBUS_CMD_FREE: {
		struct kdbus_cmd_free cmd_free;

		if (!kdbus_conn_is_ordinary(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		/* free the memory used in the receiver's pool */
		ret = copy_from_user(&cmd_free, buf, sizeof(cmd_free));
		if (ret < 0)
			break;

		ret = kdbus_negotiate_flags(&cmd_free, buf, typeof(cmd_free),
					    0);
		if (ret < 0)
			break;

		ret = kdbus_pool_release_offset(conn->pool, cmd_free.offset);
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kdbus_conn_release(conn);
	kfree(free_ptr);
	return ret;
}

/* kdbus endpoint commands for endpoint owners */
static long handle_ep_ioctl_owner(struct file *file, unsigned int cmd,
				  void __user *buf)
{
	struct kdbus_handle_ep *handle = file->private_data;
	struct kdbus_ep *ep = handle->ep_owner;
	void *free_ptr = NULL;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_ENDPOINT_UPDATE: {
		struct kdbus_cmd_update *cmd_update;

		/* update the properties of a custom endpoint */
		cmd_update = kdbus_memdup_user(buf, sizeof(*cmd_update),
					       KDBUS_UPDATE_MAX_SIZE);
		if (IS_ERR(cmd_update)) {
			ret = PTR_ERR(cmd_update);
			break;
		}

		free_ptr = cmd_update;

		ret = kdbus_negotiate_flags(cmd_update, buf,
					    typeof(*cmd_update), 0);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(cmd_update->items,
					   KDBUS_ITEMS_SIZE(cmd_update, items));
		if (ret < 0)
			break;

		ret = kdbus_ep_policy_set(ep, cmd_update->items,
					  KDBUS_ITEMS_SIZE(cmd_update, items));
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(free_ptr);
	return ret;
}

static long handle_ep_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct kdbus_handle_ep *handle = file->private_data;
	void __user *argp = (void __user *)arg;
	enum kdbus_handle_ep_type type;

	/* lock while accessing handle->type to enforce barriers */
	mutex_lock(&handle->lock);
	type = handle->type;
	mutex_unlock(&handle->lock);

	switch (type) {
	case KDBUS_HANDLE_EP_NONE:
		return handle_ep_ioctl_none(file, cmd, argp);

	case KDBUS_HANDLE_EP_CONNECTED:
		return handle_ep_ioctl_connected(file, cmd, argp);

	case KDBUS_HANDLE_EP_OWNER:
		return handle_ep_ioctl_owner(file, cmd, argp);

	default:
		return -EBADFD;
	}
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
	struct kdbus_cmd_make *make;
	struct kdbus_bus *bus;
	int ret;

	/* catch double BUS_MAKE early, locked test is below */
	if (file->private_data)
		return -EBADFD;

	make = kdbus_memdup_user(buf, sizeof(*make), KDBUS_MAKE_MAX_SIZE);
	if (IS_ERR(make))
		return PTR_ERR(make);

	ret = kdbus_negotiate_flags(make, buf, struct kdbus_cmd_make,
				    KDBUS_MAKE_ACCESS_GROUP |
				    KDBUS_MAKE_ACCESS_WORLD);
	if (ret < 0)
		goto exit;

	ret = kdbus_items_validate(make->items, KDBUS_ITEMS_SIZE(make, items));
	if (ret < 0)
		goto exit;

	bus = kdbus_bus_new(domain, make, current_fsuid(), current_fsgid());
	if (IS_ERR(bus)) {
		ret = PTR_ERR(bus);
		goto exit;
	}

	ret = kdbus_bus_activate(bus);
	if (ret < 0)
		goto exit_bus_unref;

	/* protect against parallel ioctls */
	mutex_lock(&domain->lock);
	if (file->private_data)
		ret = -EBADFD;
	else
		file->private_data = bus;
	mutex_unlock(&domain->lock);

	if (ret < 0)
		goto exit_bus_unref;

	goto exit;

exit_bus_unref:
	kdbus_bus_deactivate(bus);
	kdbus_bus_unref(bus);
exit:
	kfree(make);
	return ret;
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
