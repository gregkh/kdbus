/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
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
#include "memfd.h"
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
 * @KDBUS_HANDLE_DISCONNECTED:		Handle is disconnected
 */
enum kdbus_handle_type {
	_KDBUS_HANDLE_NULL,
	KDBUS_HANDLE_CONTROL,
	KDBUS_HANDLE_CONTROL_DOMAIN_OWNER,
	KDBUS_HANDLE_CONTROL_BUS_OWNER,
	KDBUS_HANDLE_EP,
	KDBUS_HANDLE_EP_CONNECTED,
	KDBUS_HANDLE_EP_OWNER,
	KDBUS_HANDLE_DISCONNECTED,
};

/**
 * struct kdbus_handle - a handle to the kdbus system
 * @type:	Type of this handle (KDBUS_HANDLE_*)
 * @domain:		Domain for this handle
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
	 * The higher 32bit are considered 'incompatible
	 * flags'. Refuse them all for now.
	 */
	return kernel_flags <= 0xffffffffULL;
}

static int kdbus_memdup_user(void __user *user_ptr,
			     void **out, u64 *size_out,
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
	if (size_out)
		*size_out = size;

	return 0;
}

static int kdbus_handle_memfd(void __user *buf)
{
	struct kdbus_cmd_memfd_make *m = NULL;
	const struct kdbus_item *item;
	const char *n = NULL;
	int __user *addr;
	int fd, ret;

	ret = kdbus_memdup_user(buf, (void **)&m, NULL,
				sizeof(struct kdbus_cmd_memfd_make),
				sizeof(struct kdbus_cmd_memfd_make) +
					KDBUS_MAKE_MAX_SIZE);
	if (ret < 0)
		return ret;

	KDBUS_ITEMS_FOREACH(item, m->items, KDBUS_ITEMS_SIZE(m, items)) {
		if (!KDBUS_ITEM_VALID(item, &m->items,
				      KDBUS_ITEMS_SIZE(m, items))) {
			ret = -EINVAL;
			goto exit;
		}

		switch (item->type) {
		case KDBUS_ITEM_MEMFD_NAME:
			if (n) {
				ret = -EEXIST;
				goto exit;
			}

			ret = kdbus_item_validate_name(item);
			if (ret < 0)
				goto exit;

			n = item->str;
			break;
		}
	}

	if (!KDBUS_ITEMS_END(item, m->items, KDBUS_ITEMS_SIZE(m, items))) {
		ret = -EINVAL;
		goto exit;
	}

	ret = kdbus_memfd_new(n, m->file_size, &fd);
	if (ret < 0)
		goto exit;

	/* return fd number to caller */
	addr = buf + offsetof(struct kdbus_cmd_memfd_make, fd);
	if (put_user(fd, addr)) {
		sys_close(fd);
		ret = -EFAULT;
		goto exit;
	}

exit:
	kfree(m);
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

		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_make),
					KDBUS_MAKE_MAX_SIZE);
		if (ret < 0)
			break;

		make = p;
		ret = kdbus_bus_make_user(make, &name, &bloom);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(make->flags)) {
			ret = -ENOTSUPP;
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
		handle->type = KDBUS_HANDLE_CONTROL_BUS_OWNER;
		handle->bus_owner = bus;
		break;
	}

	case KDBUS_CMD_DOMAIN_MAKE: {
		char *name;

		if (!capable(CAP_IPC_OWNER)) {
			ret = -EPERM;
			break;
		}

		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_make),
					KDBUS_MAKE_MAX_SIZE);
		if (ret < 0)
			break;

		make = p;
		ret = kdbus_domain_make_user(make, &name);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(make->flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (make->flags & KDBUS_MAKE_ACCESS_WORLD)
			mode = 0666;

		ret = kdbus_domain_new(handle->domain, name, mode, &domain);
		if (ret < 0)
			break;

		/* turn the control fd into a new domain owner device */
		handle->type = KDBUS_HANDLE_CONTROL_DOMAIN_OWNER;
		handle->domain_owner = domain;
		break;
	}

	case KDBUS_CMD_MEMFD_NEW:
		ret = kdbus_handle_memfd(buf);
		break;

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
			ret = -EFAULT;
			break;
		}

		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_make),
					KDBUS_MAKE_MAX_SIZE);
		if (ret < 0)
			break;

		make = p;
		ret = kdbus_ep_make_user(make, &name);
		if (ret < 0)
			break;

		if (!kdbus_check_flags(make->flags)) {
			ret = -ENOTSUPP;
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
			kdbus_ep_unref(ep);
			break;
		}

		/*
		 * Get an anonymous user to account messages against; custom
		 * endpoint users do not share the budget with the ordinary
		 * users created for a UID.
		 */
		ep->user = kdbus_domain_user_find_or_new(handle->ep->bus->domain,
							 INVALID_UID);
		if (!ep->user) {
			kdbus_ep_unref(ep);
			ret = -ENOMEM;
			break;
		}

		handle->ep_owner = ep;
		handle->type = KDBUS_HANDLE_EP_OWNER;
		break;
	}

	case KDBUS_CMD_HELLO: {
		/* turn this fd into a connection. */
		struct kdbus_cmd_hello *hello;

		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_hello),
					KDBUS_HELLO_MAX_SIZE);
		if (ret < 0)
			break;

		hello = p;

		if (!kdbus_check_flags(hello->conn_flags)) {
			ret = -ENOTSUPP;
			break;
		}

		if (hello->pool_size == 0 ||
		    !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
			ret = -EFAULT;
			break;
		}

		ret = kdbus_conn_new(handle->ep, hello, handle->meta,
				     &handle->conn);
		if (ret < 0)
			break;

		handle->type = KDBUS_HANDLE_EP_CONNECTED;

		if (copy_to_user(buf, p, sizeof(struct kdbus_cmd_hello))) {
			kdbus_conn_unref(handle->conn);
			ret = -EFAULT;
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

/* kdbus endpoint commands for connected peers */
static long kdbus_handle_ioctl_ep_connected(struct file *file, unsigned int cmd,
					    void __user *buf)
{
	struct kdbus_handle *handle = file->private_data;
	struct kdbus_conn *conn = handle->conn;
	void *p = NULL;
	long ret = 0;
	u64 size;

	switch (cmd) {
	case KDBUS_CMD_BYEBYE:
		ret = kdbus_conn_disconnect(conn, true);
		break;

	case KDBUS_CMD_NAME_ACQUIRE:
		/* acquire a well-known name */

		ret = kdbus_memdup_user(buf, &p, &size,
					sizeof(struct kdbus_cmd_name),
					sizeof(struct kdbus_cmd_name) +
						KDBUS_NAME_MAX_LEN + 1);
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_acquire(conn->bus->name_registry, conn, p);
		if (ret < 0)
			break;

		/* return flags to the caller */
		if (copy_to_user(buf, p, size))
			ret = -EFAULT;

		break;

	case KDBUS_CMD_NAME_RELEASE:
		/* release a well-known name */

		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_name),
					sizeof(struct kdbus_cmd_name) +
						KDBUS_NAME_MAX_LEN + 1);
		if (ret < 0)
			break;

		ret = kdbus_cmd_name_release(conn->bus->name_registry, conn, p);
		break;

	case KDBUS_CMD_NAME_LIST: {
		struct kdbus_cmd_name_list *cmd;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf))
			return -EFAULT;

		/* query current IDs and names */
		p = memdup_user(buf, sizeof(struct kdbus_cmd_name_list));
		if (IS_ERR(p))
			return PTR_ERR(p);

		cmd = p;
		ret = kdbus_cmd_name_list(conn->bus->name_registry, conn, cmd);
		if (ret < 0)
			break;

		/* return allocated data */
		if (kdbus_offset_set_user(&cmd->offset, buf,
					  struct kdbus_cmd_name_list))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_INFO: {
		struct kdbus_cmd_conn_info *cmd;

		/* return the properties of a connection */
		ret = kdbus_memdup_user(buf, &p, &size,
					sizeof(struct kdbus_cmd_conn_info),
					sizeof(struct kdbus_cmd_conn_info) +
						KDBUS_NAME_MAX_LEN + 1);
		if (ret < 0)
			break;

		cmd = p;
		ret = kdbus_cmd_conn_info(conn, cmd, size);
		if (ret < 0)
			break;

		if (kdbus_offset_set_user(&cmd->offset, buf,
					  struct kdbus_cmd_conn_info))
			ret = -EFAULT;

		break;
	}

	case KDBUS_CMD_CONN_UPDATE:
		/* update flags for a connection */
		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_update),
					sizeof(struct kdbus_cmd_update) +
						KDBUS_UPDATE_MAX_SIZE);
		if (ret < 0)
			break;

		ret = kdbus_cmd_conn_update(conn, p);
		break;

	case KDBUS_CMD_MATCH_ADD:
		/* subscribe to/filter for broadcast messages */
		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_match),
					sizeof(struct kdbus_cmd_match) +
						KDBUS_MATCH_MAX_SIZE);
		if (ret < 0)
			break;

		ret = kdbus_match_db_add(conn, p);
		break;

	case KDBUS_CMD_MATCH_REMOVE:
		/* unsubscribe from broadcast messages */
		ret = kdbus_memdup_user(buf, &p, NULL,
					sizeof(struct kdbus_cmd_match),
					sizeof(struct kdbus_cmd_match));
		if (ret < 0)
			break;

		ret = kdbus_match_db_remove(conn, p);
		break;

	case KDBUS_CMD_MSG_SEND: {
		/* submit a message which will be queued in the receiver */
		struct kdbus_kmsg *kmsg = NULL;

		if (handle->conn->flags & KDBUS_HELLO_ACTIVATOR) {
			ret = -EPERM;
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

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf))
			return -EFAULT;

		/* handle a queued message */
		if (copy_from_user(&cmd, buf, sizeof(cmd)))
			return -EFAULT;

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

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf))
			return -EFAULT;

		/* cancel sync message send requests by cookie */
		if (copy_from_user(&cookie, buf, sizeof(cookie)))
			return -EFAULT;

		ret = kdbus_cmd_msg_cancel(conn, cookie);
		break;
	}

	case KDBUS_CMD_FREE: {
		u64 off;
		struct kdbus_pool_slice *slice;

		if (!KDBUS_IS_ALIGNED8((uintptr_t)buf))
			return -EFAULT;

		/* free the memory used in the receiver's pool */
		if (copy_from_user(&off, buf, sizeof(off)))
			return -EFAULT;

		slice = kdbus_pool_slice_find(conn->pool, off);
		if (!slice)
			return -ENXIO;
		kdbus_pool_slice_free(slice);
		break;
	}

	case KDBUS_CMD_MEMFD_NEW:
		ret = kdbus_handle_memfd(buf);
		break;

	default:
		ret = -ENOTTY;
		break;
	}

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

		/* update flags for a connection */
		ret = kdbus_memdup_user(buf, &p, NULL,
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

	switch (handle->type) {
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
	struct kdbus_conn *conn = handle->conn;
	unsigned int mask = 0;

	/* Only a connected endpoint can read/write data */
	if (handle->type != KDBUS_HANDLE_EP_CONNECTED)
		return POLLERR | POLLHUP;

	poll_wait(file, &conn->wait, wait);

	mutex_lock(&conn->lock);
	if (unlikely(conn->disconnected))
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
