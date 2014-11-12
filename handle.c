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

#include <linux/device.h>
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
 * enum kdbus_handle_type - type a handle can be of
 * @KDBUS_HANDLE_CONTROL:		New file descriptor of a control node
 * @KDBUS_HANDLE_CONTROL_DOMAIN_OWNER:	File descriptor to hold a domain
 * @KDBUS_HANDLE_CONTROL_BUS_OWNER:	File descriptor to hold a bus
 * @KDBUS_HANDLE_ENDPOINT:		New file descriptor of a bus node
 * @KDBUS_HANDLE_ENDPOINT_CONNECTED:	A bus connection after HELLO
 * @KDBUS_HANDLE_ENDPOINT_OWNER:	File descriptor to hold an endpoint
 */
enum kdbus_handle_type {
	KDBUS_HANDLE_CONTROL,
	KDBUS_HANDLE_CONTROL_DOMAIN_OWNER,
	KDBUS_HANDLE_CONTROL_BUS_OWNER,
	KDBUS_HANDLE_ENDPOINT,
	KDBUS_HANDLE_ENDPOINT_CONNECTED,
	KDBUS_HANDLE_ENDPOINT_OWNER,
};

/**
 * struct kdbus_handle - a handle to the kdbus system
 * @type:		Type of this handle (KDBUS_HANDLE_*)
 * @domain:		Domain for this handle
 * @meta:		Cached connection creator's metadata/credentials
 * @ep:			The endpoint for this handle, in case @type is
 *			KDBUS_HANDLE_ENDPOINT, KDBUS_HANDLE_ENDPOINT_OWNER or
 *			KDBUS_HANDLE_ENDPOINT_CONNECTED
 * @ptr:		Generic pointer used as alias for other members
 *			in the same union by kdbus_handle_transform()
 * @domain_owner:	The domain this handle owns, in case @type
 *			is KDBUS_HANDLE_CONTROL_DOMAIN_OWNER
 * @bus_owner:		The bus this handle owns, in case @type
 *			is KDBUS_HANDLE_CONTROL_BUS_OWNER
 * @ep_owner:		The endpoint this handle owns, in case @type
 *			is KDBUS_HANDLE_ENDPOINT_OWNER
 * @conn:		The connection this handle owns, in case @type
 *			is KDBUS_HANDLE_ENDPOINT, after HELLO it is
 *			KDBUS_HANDLE_ENDPOINT_CONNECTED
 * @privileged:		Flag to mark a handle as privileged
 */
struct kdbus_handle {
	enum kdbus_handle_type type;
	struct kdbus_domain *domain;
	struct kdbus_meta *meta;
	struct kdbus_ep *ep;
	union {
		void *ptr;
		struct kdbus_domain *domain_owner;
		struct kdbus_bus *bus_owner;
		struct kdbus_ep *ep_owner;
		struct kdbus_conn *conn;
	};
	bool privileged:1;
};

static int kdbus_handle_open(struct inode *inode, struct file *file)
{
	struct kdbus_domain *domain;
	struct kdbus_handle *handle;
	struct kdbus_node *node;
	int ret;

	if (file->private_data)
		node = kdbus_node_find_by_id((long)file->private_data);
	else
		node = kdbus_node_find_by_id(MINOR(inode->i_rdev));
	if (!node)
		return -ESHUTDOWN;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle) {
		ret = -ENOMEM;
		goto exit_node;
	}

	file->private_data = handle;

	switch (node->type) {
	case KDBUS_NODE_CONTROL:
		domain = kdbus_domain_from_node(node->parent);
		handle->type = KDBUS_HANDLE_CONTROL;
		handle->domain = kdbus_domain_ref(domain);

		if (ns_capable(&init_user_ns, CAP_IPC_OWNER))
			handle->privileged = true;

		break;

	case KDBUS_NODE_ENDPOINT:
		handle->type = KDBUS_HANDLE_ENDPOINT;
		handle->ep = kdbus_ep_ref(kdbus_ep_from_node(node));
		handle->domain = kdbus_domain_ref(handle->ep->bus->domain);

		if (ns_capable(&init_user_ns, CAP_IPC_OWNER) ||
		    uid_eq(handle->ep->bus->node.uid, file->f_cred->fsuid))
			handle->privileged = true;

		/* cache the metadata/credentials of the creator */
		handle->meta = kdbus_meta_new();
		if (IS_ERR(handle->meta)) {
			ret = PTR_ERR(handle->meta);
			goto exit_free;
		}

		ret = kdbus_meta_append(handle->meta, NULL, 0,
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

		break;

	default:
		ret = -EINVAL;
		goto exit_free;
	}

	kdbus_node_release(node);
	kdbus_node_unref(node);

	return 0;

exit_free:
	kdbus_meta_free(handle->meta);
	kdbus_domain_unref(handle->domain);
	kdbus_ep_unref(handle->ep);
	kfree(handle);
exit_node:
	kdbus_node_release(node);
	kdbus_node_unref(node);
	return ret;
}

static int kdbus_handle_release(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle = file->private_data;

	switch (handle->type) {
	case KDBUS_HANDLE_CONTROL_DOMAIN_OWNER:
		kdbus_domain_deactivate(handle->domain_owner);
		kdbus_domain_unref(handle->domain_owner);
		break;

	case KDBUS_HANDLE_CONTROL_BUS_OWNER:
		kdbus_bus_deactivate(handle->bus_owner);
		kdbus_bus_unref(handle->bus_owner);
		break;

	case KDBUS_HANDLE_ENDPOINT_OWNER:
		kdbus_ep_deactivate(handle->ep_owner);
		kdbus_ep_unref(handle->ep_owner);
		break;

	case KDBUS_HANDLE_ENDPOINT_CONNECTED:
		kdbus_conn_disconnect(handle->conn, false);
		kdbus_conn_unref(handle->conn);
		break;

	case KDBUS_HANDLE_CONTROL:
	case KDBUS_HANDLE_ENDPOINT:
		/* nothing to clean up */
		break;
	}

	kdbus_meta_free(handle->meta);
	kdbus_domain_unref(handle->domain);
	kdbus_ep_unref(handle->ep);
	kfree(handle);

	return 0;
}

static int kdbus_copy_from_user(void *dest,
				void __user *user_ptr,
				size_t size)
{
	if (!KDBUS_IS_ALIGNED8((uintptr_t)user_ptr))
		return -EFAULT;

	if (copy_from_user(dest, user_ptr, size))
		return -EFAULT;

	return 0;
}

static void *kdbus_memdup_user(void __user *user_ptr,
			       size_t size_min,
			       size_t size_max)
{
	u64 size;
	int ret;

	ret = kdbus_copy_from_user(&size, user_ptr, sizeof(size));
	if (ret < 0)
		return ERR_PTR(ret);

	if (size < size_min)
		return ERR_PTR(-EINVAL);

	if (size > size_max)
		return ERR_PTR(-EMSGSIZE);

	return memdup_user(user_ptr, size);
}

static int kdbus_handle_transform(struct kdbus_handle *handle,
				  enum kdbus_handle_type old_type,
				  enum kdbus_handle_type new_type,
				  void *ctx_ptr)
{
	int ret = -EBADFD;

	/*
	 * This transforms a handle from one state into another. Only a single
	 * transformation is allowed per handle, and it must be one of:
	 *   CONTROL -> CONTROL_DOMAIN_OWNER
	 *           -> CONTROL_BUS_OWNER
	 *        EP -> EP_CONNECTED
	 *           -> EP_OWNER
	 *
	 * State transformations are protected by the domain-lock. If another
	 * transformation runs in parallel, we will fail and the caller has to
	 * revert any previous steps.
	 *
	 * We also update any context before we write the new type. Reads can
	 * now be sure that iff a specific non-entry type is set, the context
	 * is accessible, too (given appropriate read-barriers).
	 */

	WARN_ON(old_type != KDBUS_HANDLE_CONTROL &&
		old_type != KDBUS_HANDLE_ENDPOINT);
	WARN_ON(old_type == KDBUS_HANDLE_CONTROL &&
		(new_type != KDBUS_HANDLE_CONTROL_DOMAIN_OWNER &&
		 new_type != KDBUS_HANDLE_CONTROL_BUS_OWNER));
	WARN_ON(old_type == KDBUS_HANDLE_ENDPOINT &&
		(new_type != KDBUS_HANDLE_ENDPOINT_CONNECTED &&
		 new_type != KDBUS_HANDLE_ENDPOINT_OWNER));

	mutex_lock(&handle->domain->lock);
	if (handle->type == old_type) {
		handle->ptr = ctx_ptr;
		/* make sure handle->XYZ is accessible before the type is set */
		smp_wmb();
		handle->type = new_type;
		ret = 0;
	}
	mutex_unlock(&handle->domain->lock);

	return ret;
}

/* kdbus control device commands */
static long kdbus_handle_ioctl_control(struct file *file, unsigned int cmd,
				       void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_bus *bus = NULL;
	struct kdbus_cmd_make *make;
	struct kdbus_domain *domain = NULL;
	umode_t mode = 0600;
	void *free_ptr = NULL;
	int ret;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE: {
		kgid_t gid = KGIDT_INIT(0);

		make = kdbus_memdup_user(buf, sizeof(*make),
					 KDBUS_MAKE_MAX_SIZE);
		if (IS_ERR(make)) {
			ret = PTR_ERR(make);
			break;
		}

		free_ptr = make;

		ret = kdbus_negotiate_flags(make, buf, typeof(*make),
					    KDBUS_MAKE_ACCESS_GROUP |
					    KDBUS_MAKE_ACCESS_WORLD);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(make->items,
					   KDBUS_ITEMS_SIZE(make, items));
		if (ret < 0)
			break;

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (make->flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		bus = kdbus_bus_new(handle->domain, make,
				    mode, current_fsuid(), gid);
		if (IS_ERR(bus)) {
			ret = PTR_ERR(bus);
			break;
		}

		ret = kdbus_bus_activate(bus);
		if (ret < 0) {
			kdbus_bus_unref(bus);
			break;
		}

		/* turn the control fd into a new bus owner device */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_CONTROL,
					     KDBUS_HANDLE_CONTROL_BUS_OWNER,
					     bus);
		if (ret < 0) {
			kdbus_bus_deactivate(bus);
			kdbus_bus_unref(bus);
			break;
		}

		break;
	}

	case KDBUS_CMD_DOMAIN_MAKE: {
		const char *name;

		if (!handle->privileged) {
			ret = -EPERM;
			break;
		}

		make = kdbus_memdup_user(buf, sizeof(*make),
					 KDBUS_MAKE_MAX_SIZE);
		if (IS_ERR(make)) {
			ret = PTR_ERR(make);
			break;
		}

		free_ptr = make;

		ret = kdbus_negotiate_flags(make, buf, typeof(*make),
					    KDBUS_MAKE_ACCESS_GROUP |
					    KDBUS_MAKE_ACCESS_WORLD);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(make->items,
					   KDBUS_ITEMS_SIZE(make, items));
		if (ret < 0)
			break;

		name = kdbus_items_get_str(make->items,
					   KDBUS_ITEMS_SIZE(make, items),
					   KDBUS_ITEM_MAKE_NAME);
		if (IS_ERR(name)) {
			ret = PTR_ERR(name);
			break;
		}

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD)
			mode = 0666;

		domain = kdbus_domain_new(handle->domain, name, mode);
		if (IS_ERR(domain)) {
			ret = PTR_ERR(domain);
			break;
		}

		ret = kdbus_domain_activate(domain);
		if (ret < 0) {
			kdbus_domain_unref(domain);
			break;
		}

		/* turn the control fd into a new domain owner device */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_CONTROL,
					     KDBUS_HANDLE_CONTROL_DOMAIN_OWNER,
					     domain);
		if (ret < 0) {
			kdbus_domain_deactivate(domain);
			kdbus_domain_unref(domain);
			break;
		}

		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(free_ptr);

	return ret;
}

/* kdbus endpoint make commands */
static long kdbus_handle_ioctl_ep(struct file *file, unsigned int cmd,
				  void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	void *free_ptr = NULL;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_ENDPOINT_MAKE: {
		struct kdbus_cmd_make *make;
		umode_t mode = 0600;
		kgid_t gid = KGIDT_INIT(0);
		const char *name;
		struct kdbus_ep *ep;

		/* creating custom endpoints is a privileged operation */
		if (!handle->privileged) {
			ret = -EPERM;
			break;
		}

		make = kdbus_memdup_user(buf, sizeof(*make),
					 KDBUS_MAKE_MAX_SIZE);
		if (IS_ERR(make)) {
			ret = PTR_ERR(make);
			break;
		}

		free_ptr = make;

		ret = kdbus_negotiate_flags(make, buf, typeof(*make),
					    KDBUS_MAKE_ACCESS_GROUP |
					    KDBUS_MAKE_ACCESS_WORLD);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(make->items,
					   KDBUS_ITEMS_SIZE(make, items));
		if (ret < 0)
			break;

		name = kdbus_items_get_str(make->items,
					   KDBUS_ITEMS_SIZE(make, items),
					   KDBUS_ITEM_MAKE_NAME);
		if (IS_ERR(name)) {
			ret = PTR_ERR(name);
			break;
		}

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (make->flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		/* custom endpoints always have a policy db */
		ep = kdbus_ep_new(handle->ep->bus, name, mode,
				  current_fsuid(), gid, true);
		if (IS_ERR(ep)) {
			ret = PTR_ERR(ep);
			break;
		}

		ret = kdbus_ep_activate(ep);
		if (ret < 0) {
			kdbus_ep_unref(ep);
			break;
		}

		ret = kdbus_ep_policy_set(ep, make->items,
					  KDBUS_ITEMS_SIZE(make, items));
		if (ret < 0) {
			kdbus_ep_deactivate(ep);
			kdbus_ep_unref(ep);
			break;
		}

		/*
		 * Get an anonymous user to account messages against; custom
		 * endpoint users do not share the budget with the ordinary
		 * users created for a UID.
		 */
		ep->user = kdbus_domain_get_user(handle->ep->bus->domain,
						 INVALID_UID);
		if (IS_ERR(ep->user)) {
			ret = PTR_ERR(ep->user);
			kdbus_ep_deactivate(ep);
			kdbus_ep_unref(ep);
			break;
		}

		/* turn the ep fd into a new endpoint owner device */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_ENDPOINT,
					     KDBUS_HANDLE_ENDPOINT_OWNER, ep);
		if (ret < 0) {
			kdbus_ep_deactivate(ep);
			kdbus_ep_unref(ep);
			break;
		}

		break;
	}

	case KDBUS_CMD_HELLO: {
		struct kdbus_cmd_hello *hello;
		struct kdbus_conn *conn = NULL;

		hello = kdbus_memdup_user(buf, sizeof(*hello),
					  KDBUS_HELLO_MAX_SIZE);
		if (IS_ERR(hello)) {
			ret = PTR_ERR(hello);
			break;
		}

		free_ptr = hello;

		ret = kdbus_negotiate_flags(hello, buf, typeof(*hello),
					    KDBUS_HELLO_ACCEPT_FD |
					    KDBUS_HELLO_ACTIVATOR |
					    KDBUS_HELLO_POLICY_HOLDER |
					    KDBUS_HELLO_MONITOR);
		if (ret < 0)
			break;

		ret = kdbus_items_validate(hello->items,
					   KDBUS_ITEMS_SIZE(hello, items));
		if (ret < 0)
			break;

		if (hello->pool_size == 0 ||
		    !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
			ret = -EFAULT;
			break;
		}

		conn = kdbus_conn_new(handle->ep, hello, handle->meta,
				      handle->privileged);
		if (IS_ERR(conn)) {
			ret = PTR_ERR(conn);
			break;
		}

		/* turn the ep fd into a new connection */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_ENDPOINT,
					     KDBUS_HANDLE_ENDPOINT_CONNECTED,
					     conn);
		if (ret < 0) {
			kdbus_conn_disconnect(conn, false);
			kdbus_conn_unref(conn);
			break;
		}

		if (copy_to_user(buf, hello, sizeof(*hello)))
			ret = -EFAULT;

		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(free_ptr);

	return ret;
}

/* kdbus endpoint commands for connected peers */
static long kdbus_handle_ioctl_ep_connected(struct file *file, unsigned int cmd,
					    void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
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

		ret = kdbus_cmd_name_acquire(conn->bus->name_registry, conn,
					     cmd_name);
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

		ret = kdbus_cmd_name_release(conn->bus->name_registry, conn,
					     cmd_name);
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

		ret = kdbus_cmd_name_list(conn->bus->name_registry,
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
static long kdbus_handle_ioctl_ep_owner(struct file *file, unsigned int cmd,
					void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
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

static long kdbus_handle_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct kdbus_handle *handle = file->private_data;
	void __user *argp = (void __user *)arg;
	enum kdbus_handle_type type = handle->type;

	/* make sure all handle fields are set if handle->type is */
	smp_rmb();

	switch (type) {
	case KDBUS_HANDLE_CONTROL:
		return kdbus_handle_ioctl_control(file, cmd, argp);

	case KDBUS_HANDLE_ENDPOINT:
		return kdbus_handle_ioctl_ep(file, cmd, argp);

	case KDBUS_HANDLE_ENDPOINT_CONNECTED:
		return kdbus_handle_ioctl_ep_connected(file, cmd, argp);

	case KDBUS_HANDLE_ENDPOINT_OWNER:
		return kdbus_handle_ioctl_ep_owner(file, cmd, argp);

	default:
		return -EBADFD;
	}
}

static unsigned int kdbus_handle_poll(struct file *file,
				      struct poll_table_struct *wait)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_conn *conn;
	unsigned int mask = POLLOUT | POLLWRNORM;

	/* Only a connected endpoint can read/write data */
	if (handle->type != KDBUS_HANDLE_ENDPOINT_CONNECTED)
		return POLLERR | POLLHUP;

	/* make sure handle->conn is set if handle->type is */
	smp_rmb();
	conn = handle->conn;

	poll_wait(file, &conn->wait, wait);

	mutex_lock(&conn->lock);
	if (!kdbus_conn_active(conn))
		mask = POLLERR | POLLHUP;
	else if (!list_empty(&conn->queue.msg_list))
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&conn->lock);

	return mask;
}

static int kdbus_handle_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kdbus_handle *handle = file->private_data;

	if (handle->type != KDBUS_HANDLE_ENDPOINT_CONNECTED)
		return -EPERM;

	/* make sure handle->conn is set if handle->type is */
	smp_rmb();

	return kdbus_pool_mmap(handle->conn->pool, vma);
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
