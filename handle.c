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
#include "match.h"
#include "message.h"
#include "metadata.h"
#include "names.h"
#include "domain.h"
#include "notify.h"
#include "policy.h"

/**
 * enum kdbus_handle_type - type a handle can be of
 * @_KDBUS_HANDLE_NULL:			Uninitialized/invalid
 * @KDBUS_HANDLE_CONTROL:		New file descriptor of a control node
 * @KDBUS_HANDLE_CONTROL_DOMAIN_OWNER:	File descriptor to hold a domain
 * @KDBUS_HANDLE_CONTROL_BUS_OWNER:	File descriptor to hold a bus
 * @KDBUS_HANDLE_EP:			New file descriptor of a bus node
 * @KDBUS_HANDLE_EP_CONNECTED:		A bus connection after HELLO
 * @KDBUS_HANDLE_EP_OWNER:		File descriptor to hold an endpoint
 */
enum kdbus_handle_type {
	_KDBUS_HANDLE_NULL,
	KDBUS_HANDLE_CONTROL,
	KDBUS_HANDLE_CONTROL_DOMAIN_OWNER,
	KDBUS_HANDLE_CONTROL_BUS_OWNER,
	KDBUS_HANDLE_EP,
	KDBUS_HANDLE_EP_CONNECTED,
	KDBUS_HANDLE_EP_OWNER,
};

/**
 * struct kdbus_handle - a handle to the kdbus system
 * @type:	Type of this handle (KDBUS_HANDLE_*)
 * @domain:	Domain for this handle
 * @meta:	Cached connection creator's metadata/credentials
 * @ep:		The endpoint this handle owns, in case @type
 *		is KDBUS_HANDLE_EP
 * @domain_owner:	The domain this handle owns, in case @type
 *		is KDBUS_HANDLE_CONTROL_DOMAIN_OWNER
 * @bus_owner:	The bus this handle owns, in case @type
 *		is KDBUS_HANDLE_CONTROL_BUS_OWNER
 * @ep_owner	The endpoint this handle owns, in case @type
 *		is KDBUS_HANDLE_EP_OWNER
 * @conn	The connection this handle owns, in case @type
 *		is KDBUS_HANDLE_EP, after HELLO it is
 *		KDBUS_HANDLE_EP_CONNECTED
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
};

static int kdbus_handle_open(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle;
	struct kdbus_domain *domain;
	struct kdbus_ep *ep;
	int ret;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* find and reference domain */
	domain = kdbus_domain_find_by_major(MAJOR(inode->i_rdev));
	if (!domain || domain->disconnected) {
		kfree(handle);
		return -ESHUTDOWN;
	}
	handle->domain = domain;
	file->private_data = handle;

	/* control device node */
	if (MINOR(inode->i_rdev) == 0) {
		handle->type = KDBUS_HANDLE_CONTROL;
		return 0;
	}

	/* find endpoint for device node */
	mutex_lock(&handle->domain->lock);
	ep = idr_find(&handle->domain->idr, MINOR(inode->i_rdev));
	if (!ep || ep->disconnected) {
		ret = -ESHUTDOWN;
		goto exit_unlock;
	}

	/* create endpoint connection */
	handle->type = KDBUS_HANDLE_EP;
	handle->ep = kdbus_ep_ref(ep);

	/* cache the metadata/credentials of the creator of the connection */
	ret = kdbus_meta_new(&handle->meta);
	if (ret < 0)
		goto exit_ep_unref;

	ret = kdbus_meta_append(handle->meta, NULL, 0,
				KDBUS_ATTACH_CREDS |
				KDBUS_ATTACH_COMM |
				KDBUS_ATTACH_EXE |
				KDBUS_ATTACH_CMDLINE |
				KDBUS_ATTACH_CGROUP |
				KDBUS_ATTACH_CAPS |
				KDBUS_ATTACH_SECLABEL |
				KDBUS_ATTACH_AUDIT);
	if (ret < 0)
		goto exit_meta_free;

	mutex_unlock(&handle->domain->lock);
	return 0;

exit_meta_free:
	kdbus_meta_free(handle->meta);
exit_ep_unref:
	kdbus_ep_unref(handle->ep);
exit_unlock:
	mutex_unlock(&handle->domain->lock);
	kdbus_domain_unref(handle->domain);
	kfree(handle);
	return ret;
}

static int kdbus_handle_release(struct inode *inode, struct file *file)
{
	struct kdbus_handle *handle = file->private_data;

	switch (handle->type) {
	case KDBUS_HANDLE_CONTROL_DOMAIN_OWNER:
		kdbus_domain_disconnect(handle->domain_owner);
		kdbus_domain_unref(handle->domain_owner);
		break;

	case KDBUS_HANDLE_CONTROL_BUS_OWNER:
		kdbus_bus_disconnect(handle->bus_owner);
		kdbus_bus_unref(handle->bus_owner);
		break;

	case KDBUS_HANDLE_EP_OWNER:
		kdbus_ep_disconnect(handle->ep_owner);
		kdbus_ep_unref(handle->ep_owner);
		break;

	case KDBUS_HANDLE_EP_CONNECTED:
		kdbus_conn_disconnect(handle->conn, false);
		kdbus_conn_unref(handle->conn);
		/* fall through */

	case KDBUS_HANDLE_EP:
		kdbus_ep_unref(handle->ep);
		break;

	default:
		break;
	}

	kdbus_meta_free(handle->meta);
	kdbus_domain_unref(handle->domain);
	kfree(handle);

	return 0;
}

static bool kdbus_check_flags(u64 kernel_flags)
{
	/*
	 * The higher 32bit are considered 'incompatible flags'.
	 * Refuse them all for now.
	 */
	return upper_32_bits(kernel_flags) == 0;
}

static int kdbus_memdup_user(void __user *user_ptr,
			     void **out,
			     size_t size_min,
			     size_t size_max)
{
	void *ptr = NULL;
	u64 size;

	if (!KDBUS_IS_ALIGNED8((uintptr_t) user_ptr))
		return -EFAULT;

	if (copy_from_user(&size, user_ptr, sizeof(size)))
		return -EFAULT;

	if (size < size_min)
		return -EINVAL;

	if (size > size_max)
		return -EMSGSIZE;

	ptr = memdup_user(user_ptr, size);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	*out = ptr;
	return 0;
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
	void *p = NULL;
	int ret;

	switch (cmd) {
	case KDBUS_CMD_BUS_MAKE: {
		kgid_t gid = KGIDT_INIT(0);
		struct kdbus_bloom_parameter bloom;
		char *name;

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_make),
					KDBUS_MAKE_MAX_SIZE);
		if (ret < 0)
			break;

		make = p;
		ret = kdbus_bus_make_user(make, &name, &bloom);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(make->flags)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (make->flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		ret = kdbus_bus_new(handle->domain, make, name, &bloom,
				    mode, current_fsuid(), gid, &bus);
		if (ret < 0)
			break;

		/* turn the control fd into a new bus owner device */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_CONTROL,
					     KDBUS_HANDLE_CONTROL_BUS_OWNER,
					     bus);
		if (ret < 0) {
			kdbus_bus_disconnect(bus);
			kdbus_bus_unref(bus);
			break;
		}

		break;
	}

	case KDBUS_CMD_DOMAIN_MAKE: {
		char *name;

		if (!capable(CAP_IPC_OWNER)) {
			ret = -EPERM;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_make),
					KDBUS_MAKE_MAX_SIZE);
		if (ret < 0)
			break;

		make = p;
		ret = kdbus_domain_make_user(make, &name);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(make->flags)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD)
			mode = 0666;

		ret = kdbus_domain_new(handle->domain, name, mode, &domain);
		if (ret < 0)
			break;

		/* turn the control fd into a new domain owner device */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_CONTROL,
					     KDBUS_HANDLE_CONTROL_DOMAIN_OWNER,
					     domain);
		if (ret < 0) {
			kdbus_domain_disconnect(domain);
			kdbus_domain_unref(domain);
			break;
		}

		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(p);

	return ret;
}

/* kdbus endpoint make commands */
static long kdbus_handle_ioctl_ep(struct file *file, unsigned int cmd,
				  void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	void *p = NULL;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_EP_MAKE: {
		struct kdbus_cmd_make *make;
		umode_t mode = 0;
		kgid_t gid = KGIDT_INIT(0);
		char *name;
		struct kdbus_ep *ep;

		/* creating custom endpoints is a privileged operation */
		if (!kdbus_bus_uid_is_privileged(handle->ep->bus)) {
			ret = -EPERM;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_make),
					KDBUS_MAKE_MAX_SIZE);
		if (ret < 0)
			break;

		make = p;
		ret = kdbus_ep_make_user(make, &name);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(make->flags)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD) {
			mode = 0666;
		} else if (make->flags & KDBUS_MAKE_ACCESS_GROUP) {
			mode = 0660;
			gid = current_fsgid();
		}

		/* custom endpoints always have a policy db */
		ret = kdbus_ep_new(handle->ep->bus, name, mode,
				   current_fsuid(), gid, true, &ep);
		if (ret < 0)
			break;

		ret = kdbus_ep_policy_set(ep, make->items,
					  KDBUS_ITEMS_SIZE(make, items));
		if (ret < 0) {
			kdbus_ep_disconnect(ep);
			kdbus_ep_unref(ep);
			break;
		}

		/*
		 * Get an anonymous user to account messages against; custom
		 * endpoint users do not share the budget with the ordinary
		 * users created for a UID.
		 */
		ret = kdbus_domain_get_user(handle->ep->bus->domain,
					    INVALID_UID, &ep->user);
		if (ret < 0) {
			kdbus_ep_disconnect(ep);
			kdbus_ep_unref(ep);
			break;
		}

		/* turn the ep fd into a new endpoint owner device */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_EP,
					     KDBUS_HANDLE_EP_OWNER, ep);
		if (ret < 0) {
			kdbus_ep_disconnect(ep);
			kdbus_ep_unref(ep);
			break;
		}

		break;
	}

	case KDBUS_CMD_HELLO: {
		struct kdbus_cmd_hello *hello;
		struct kdbus_conn *conn = NULL;

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_hello),
					KDBUS_HELLO_MAX_SIZE);
		if (ret < 0)
			break;

		hello = p;

		if (!kdbus_check_flags(hello->conn_flags)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (hello->pool_size == 0 ||
		    !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_conn_new(handle->ep, hello, handle->meta, &conn);
		if (ret < 0)
			break;

		/* turn the ep fd into a new connection */
		ret = kdbus_handle_transform(handle, KDBUS_HANDLE_EP,
					     KDBUS_HANDLE_EP_CONNECTED,
					     conn);
		if (ret < 0) {
			kdbus_conn_disconnect(conn, false);
			kdbus_conn_unref(conn);
			break;
		}

		if (copy_to_user(buf, p, sizeof(struct kdbus_cmd_hello)))
			ret = -EFAULT;

		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(p);

	return ret;
}

/* kdbus endpoint commands for connected peers */
static long kdbus_handle_ioctl_ep_connected(struct file *file, unsigned int cmd,
					    void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_conn *conn = handle->conn;
	void *p = NULL;
	long ret = 0;

	/*
	 * BYEBYE is special; we must not acquire a connection when
	 * calling into kdbus_conn_disconnect() or we will deadlock,
	 * because kdbus_conn_disconnect() will wait for all acquired
	 * references to be dropped.
	 */
	if (cmd == KDBUS_CMD_BYEBYE) {
		if (!kdbus_conn_is_connected(conn))
			return -EOPNOTSUPP;

		return kdbus_conn_disconnect(conn, true);
	}

	ret = kdbus_conn_acquire(conn);
	if (ret < 0)
		return ret;

	switch (cmd) {
	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */

		if (!kdbus_conn_is_connected(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_name),
					sizeof(struct kdbus_cmd_name) +
						KDBUS_ITEM_HEADER_SIZE +
						KDBUS_NAME_MAX_LEN + 1);
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_acquire(conn->bus->name_registry, conn, p);
		if (ret < 0)
			break;

		/* return flags to the caller */
		if (copy_to_user(buf, p, ((struct kdbus_cmd_name *)p)->size))
			ret = -EFAULT;

		break;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */

		if (!kdbus_conn_is_connected(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_name),
					sizeof(struct kdbus_cmd_name) +
						KDBUS_ITEM_HEADER_SIZE +
						KDBUS_NAME_MAX_LEN + 1);
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_release(conn->bus->name_registry, conn, p);
		break;

	case KDBUS_CMD_NAME_LIST: {
		struct kdbus_cmd_name_list cmd;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		/* query current IDs and names */
		if (copy_from_user(&cmd, buf, sizeof(cmd))) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_name_list(conn->bus->name_registry,
					  conn, &cmd);
		if (ret < 0)
			break;

		/* return allocated data */
		if (kdbus_offset_set_user(&cmd.offset, buf,
					  struct kdbus_cmd_name_list))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_INFO: {
		struct kdbus_cmd_conn_info *cmd;

		/* return the properties of a connection */
		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_conn_info),
					sizeof(struct kdbus_cmd_conn_info) +
						KDBUS_NAME_MAX_LEN + 1);
		if (ret < 0)
			break;

		cmd = p;
		ret = kdbus_cmd_conn_info(conn, cmd);
		if (ret < 0)
			break;

		if (kdbus_offset_set_user(&cmd->offset, buf,
					  struct kdbus_cmd_conn_info))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_UPDATE:
		/* update the properties of a connection */
		if (!kdbus_conn_is_connected(conn) &&
		    !kdbus_conn_is_policy_holder(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_update),
					sizeof(struct kdbus_cmd_update) +
						KDBUS_UPDATE_MAX_SIZE);
		if (ret < 0)
			break;

		ret = kdbus_cmd_conn_update(conn, p);
		break;

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */

		if (!kdbus_conn_is_connected(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_match),
					sizeof(struct kdbus_cmd_match) +
						KDBUS_MATCH_MAX_SIZE);
		if (ret < 0)
			break;

		ret = kdbus_match_db_add(conn, p);
		break;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */

		if (!kdbus_conn_is_connected(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_match),
					sizeof(struct kdbus_cmd_match));
		if (ret < 0)
			break;

		kdbus_match_db_remove(conn, p);
		break;

	case KDBUS_CMD_MSG_SEND: {
		/* submit a message which will be queued in the receiver */
		struct kdbus_kmsg *kmsg = NULL;

		if (!kdbus_conn_is_connected(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		ret = kdbus_kmsg_new_from_user(conn, buf, &kmsg);
		if (ret < 0)
			break;

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
		struct kdbus_cmd_recv cmd;

		if (!kdbus_conn_is_connected(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		/* handle a queued message */
		if (copy_from_user(&cmd, buf, sizeof(cmd))) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_msg_recv(conn, &cmd);
		if (ret < 0)
			break;

		/* return the address of the next message in the pool */
		if (kdbus_offset_set_user(&cmd.offset, buf,
					  struct kdbus_cmd_recv))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_MSG_CANCEL: {
		u64 cookie;

		if (!kdbus_conn_is_connected(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		/* cancel sync message send requests by cookie */
		if (copy_from_user(&cookie, buf, sizeof(cookie))) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_cmd_msg_cancel(conn, cookie);
		break;
	}

	case KDBUS_CMD_FREE: {
		u64 off;
		struct kdbus_pool_slice *slice;

		if (!kdbus_conn_is_connected(conn) &&
		    !kdbus_conn_is_monitor(conn)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf)) {
			ret = -EFAULT;
			break;
		}

		/* free the memory used in the receiver's pool */
		if (copy_from_user(&off, buf, sizeof(off))) {
			ret = -EFAULT;
			break;
		}

		slice = kdbus_pool_slice_find(conn->pool, off);
		if (!slice) {
			ret = -ENXIO;
			break;
		}

		if (!kdbus_pool_slice_is_public(slice)) {
			ret = -EINVAL;
			break;
		}

		kdbus_pool_slice_free(slice);
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kdbus_conn_release(conn);
	kfree(p);
	return ret;
}

/* kdbus endpoint commands for endpoint owners */
static long kdbus_handle_ioctl_ep_owner(struct file *file, unsigned int cmd,
					void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_ep *ep = handle->ep_owner;
	void *p = NULL;
	long ret = 0;

	switch (cmd) {
	case KDBUS_CMD_EP_UPDATE: {
		struct kdbus_cmd_update *cmd;

		/* update the properties of a custom endpoint */
		ret = kdbus_memdup_user(buf, &p,
					sizeof(struct kdbus_cmd_update),
					sizeof(struct kdbus_cmd_update) +
					       KDBUS_UPDATE_MAX_SIZE);
		if (ret < 0)
			break;

		cmd = p;
		ret = kdbus_ep_policy_set(ep, cmd->items,
					  KDBUS_ITEMS_SIZE(cmd, items));
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	kfree(p);
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

	case KDBUS_HANDLE_EP:
		return kdbus_handle_ioctl_ep(file, cmd, argp);

	case KDBUS_HANDLE_EP_CONNECTED:
		return kdbus_handle_ioctl_ep_connected(file, cmd, argp);

	case KDBUS_HANDLE_EP_OWNER:
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
	if (handle->type != KDBUS_HANDLE_EP_CONNECTED)
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

	if (handle->type != KDBUS_HANDLE_EP_CONNECTED)
		return -EPERM;

	/* make sure handle->conn is set if handle->type is */
	smp_rmb();

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
