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

#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/sock.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "handle.h"
#include "item.h"
#include "match.h"
#include "message.h"
#include "names.h"
#include "policy.h"

#define KDBUS_KMSG_HEADER_SIZE offsetof(struct kdbus_kmsg, msg)

static struct kdbus_msg_resources *kdbus_msg_resources_new(void)
{
	struct kdbus_msg_resources *r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);

	kref_init(&r->kref);

	return r;
}

static void __kdbus_msg_resources_free(struct kref *kref)
{
	struct kdbus_msg_resources *r =
		container_of(kref, struct kdbus_msg_resources, kref);
	size_t i;

	for (i = 0; i < r->data_count; ++i) {
		switch (r->data[i].type) {
		case KDBUS_MSG_DATA_VEC:
			/* nothing to do */
			break;
		case KDBUS_MSG_DATA_MEMFD:
			if (r->data[i].memfd.file)
				fput(r->data[i].memfd.file);
			break;
		}
	}

	for (i = 0; i < r->fds_count; i++)
		if (r->fds[i])
			fput(r->fds[i]);

	kfree(r->dst_name);
	kfree(r->data);
	kfree(r->fds);
	kfree(r);
}

/**
 * kdbus_msg_resources_ref() - Acquire reference to msg resources
 * @r:		resources to acquire ref to
 *
 * Return: The acquired resource
 */
struct kdbus_msg_resources *
kdbus_msg_resources_ref(struct kdbus_msg_resources *r)
{
	if (r)
		kref_get(&r->kref);
	return r;
}

/**
 * kdbus_msg_resources_unref() - Drop reference to msg resources
 * @r:		resources to drop reference of
 *
 * Return: NULL
 */
struct kdbus_msg_resources *
kdbus_msg_resources_unref(struct kdbus_msg_resources *r)
{
	if (r)
		kref_put(&r->kref, __kdbus_msg_resources_free);
	return NULL;
}

/**
 * kdbus_kmsg_free() - free allocated message
 * @kmsg:		Message
 */
void kdbus_kmsg_free(struct kdbus_kmsg *kmsg)
{
	if (!kmsg)
		return;

	kdbus_msg_resources_unref(kmsg->res);
	kdbus_meta_conn_unref(kmsg->conn_meta);
	kdbus_meta_proc_unref(kmsg->proc_meta);
	kfree(kmsg->iov);
	kfree(kmsg);
}

/**
 * kdbus_kmsg_new() - allocate message
 * @bus:		Bus this message is allocated on
 * @extra_size:		Additional size to reserve for data
 *
 * Return: new kdbus_kmsg on success, ERR_PTR on failure.
 */
struct kdbus_kmsg *kdbus_kmsg_new(struct kdbus_bus *bus, size_t extra_size)
{
	struct kdbus_kmsg *m;
	size_t size;
	int ret;

	size = sizeof(struct kdbus_kmsg) + KDBUS_ITEM_SIZE(extra_size);
	m = kzalloc(size, GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	m->seq = atomic64_inc_return(&bus->domain->last_id);
	m->msg.size = size - KDBUS_KMSG_HEADER_SIZE;
	m->msg.items[0].size = KDBUS_ITEM_SIZE(extra_size);

	m->proc_meta = kdbus_meta_proc_new();
	if (IS_ERR(m->proc_meta)) {
		ret = PTR_ERR(m->proc_meta);
		m->proc_meta = NULL;
		goto exit;
	}

	m->conn_meta = kdbus_meta_conn_new();
	if (IS_ERR(m->conn_meta)) {
		ret = PTR_ERR(m->conn_meta);
		m->conn_meta = NULL;
		goto exit;
	}

	return m;

exit:
	kdbus_kmsg_free(m);
	return ERR_PTR(ret);
}

static int kdbus_handle_check_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct socket *sock;

	/*
	 * Don't allow file descriptors in the transport that themselves allow
	 * file descriptor queueing. This will eventually be allowed once both
	 * unix domain sockets and kdbus share a generic garbage collector.
	 */

	if (file->f_op == &kdbus_handle_ops)
		return -EOPNOTSUPP;

	if (!S_ISSOCK(inode->i_mode))
		return 0;

	if (file->f_mode & FMODE_PATH)
		return 0;

	sock = SOCKET_I(inode);
	if (sock->sk && sock->ops && sock->ops->family == PF_UNIX)
		return -EOPNOTSUPP;

	return 0;
}

static const char * const zeros = "\0\0\0\0\0\0\0";

/*
 * kdbus_msg_scan_items() - validate incoming data and prepare parsing
 * @kmsg:		Message
 * @bus:		Bus the message is sent over
 *
 * Return: 0 on success, negative errno on failure.
 *
 * Files references in MEMFD or FDS items are pinned.
 *
 * On errors, the caller should drop any taken reference with
 * kdbus_kmsg_free()
 */
static int kdbus_msg_scan_items(struct kdbus_kmsg *kmsg,
				struct kdbus_bus *bus)
{
	struct kdbus_msg_resources *res = kmsg->res;
	const struct kdbus_msg *msg = &kmsg->msg;
	const struct kdbus_item *item;
	size_t n, n_vecs, n_memfds;
	bool has_bloom = false;
	bool has_name = false;
	bool has_fds = false;
	bool is_broadcast;
	bool is_signal;
	u64 vec_size;

	is_broadcast = (msg->dst_id == KDBUS_DST_ID_BROADCAST);
	is_signal = !!(msg->flags & KDBUS_MSG_SIGNAL);

	/* count data payloads */
	n_vecs = 0;
	n_memfds = 0;
	KDBUS_ITEMS_FOREACH(item, msg->items, KDBUS_ITEMS_SIZE(msg, items)) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC:
			++n_vecs;
			break;
		case KDBUS_ITEM_PAYLOAD_MEMFD:
			++n_memfds;
			if (item->memfd.size % 8)
				++n_vecs;
			break;
		default:
			break;
		}
	}

	n = n_vecs + n_memfds;
	if (n > 0) {
		res->data = kcalloc(n, sizeof(*res->data), GFP_KERNEL);
		if (!res->data)
			return -ENOMEM;
	}

	if (n_vecs > 0) {
		kmsg->iov = kcalloc(n_vecs, sizeof(*kmsg->iov), GFP_KERNEL);
		if (!kmsg->iov)
			return -ENOMEM;
	}

	/* import data payloads */
	n = 0;
	vec_size = 0;
	KDBUS_ITEMS_FOREACH(item, msg->items, KDBUS_ITEMS_SIZE(msg, items)) {
		size_t payload_size = KDBUS_ITEM_PAYLOAD_SIZE(item);
		struct iovec *iov = kmsg->iov + kmsg->iov_count;

		if (++n > KDBUS_MSG_MAX_ITEMS)
			return -E2BIG;

		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			struct kdbus_msg_data *d = res->data + res->data_count;
			void __force __user *ptr = KDBUS_PTR(item->vec.address);
			size_t size = item->vec.size;

			if (vec_size + size < vec_size)
				return -EMSGSIZE;
			if (vec_size + size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
				return -EMSGSIZE;

			d->type = KDBUS_MSG_DATA_VEC;
			d->size = size;

			if (ptr) {
				if (unlikely(!access_ok(VERIFY_READ, ptr,
							size)))
					return -EFAULT;

				d->vec.off = kmsg->pool_size;
				iov->iov_base = ptr;
				iov->iov_len = size;
			} else {
				d->vec.off = ~0ULL;
				iov->iov_base = (char __user *)zeros;
				iov->iov_len = size % 8;
			}

			if (kmsg->pool_size + iov->iov_len < kmsg->pool_size)
				return -EMSGSIZE;

			kmsg->pool_size += iov->iov_len;
			++kmsg->iov_count;
			++res->vec_count;
			++res->data_count;
			vec_size += size;

			break;
		}

		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			struct kdbus_msg_data *d = res->data + res->data_count;
			u64 start = item->memfd.start;
			u64 size = item->memfd.size;
			size_t pad = size % 8;
			int seals, mask;
			struct file *f;

			if (kmsg->pool_size + size % 8 < kmsg->pool_size)
				return -EMSGSIZE;
			if (start + size < start)
				return -EMSGSIZE;

			if (item->memfd.fd < 0)
				return -EBADF;

			if (res->memfd_count >= KDBUS_MSG_MAX_MEMFD_ITEMS)
				return -E2BIG;

			f = fget(item->memfd.fd);
			if (!f)
				return -EBADF;

			if (pad) {
				iov->iov_base = (char __user *)zeros;
				iov->iov_len = pad;

				kmsg->pool_size += pad;
				++kmsg->iov_count;
			}

			++res->data_count;
			++res->memfd_count;

			d->type = KDBUS_MSG_DATA_MEMFD;
			d->size = size;
			d->memfd.start = start;
			d->memfd.file = f;

			/*
			 * We only accept a sealed memfd file whose content
			 * cannot be altered by the sender or anybody else
			 * while it is shared or in-flight. Other files need
			 * to be passed with KDBUS_MSG_FDS.
			 */
			seals = shmem_get_seals(f);
			if (seals < 0)
				return -EMEDIUMTYPE;

			mask = F_SEAL_SHRINK | F_SEAL_GROW |
				F_SEAL_WRITE | F_SEAL_SEAL;
			if ((seals & mask) != mask)
				return -ETXTBSY;

			if (start + size > (u64)i_size_read(file_inode(f)))
				return -EBADF;

			break;
		}

		case KDBUS_ITEM_FDS: {
			unsigned int i;
			unsigned int fds_count = payload_size / sizeof(int);

			/* do not allow multiple fd arrays */
			if (has_fds)
				return -EEXIST;
			has_fds = true;

			/* Do not allow to broadcast file descriptors */
			if (is_broadcast)
				return -ENOTUNIQ;

			if (fds_count > KDBUS_CONN_MAX_FDS_PER_USER)
				return -EMFILE;

			res->fds = kcalloc(fds_count, sizeof(struct file *),
					   GFP_KERNEL);
			if (!res->fds)
				return -ENOMEM;

			for (i = 0; i < fds_count; i++) {
				int fd = item->fds[i];
				int ret;

				/*
				 * Verify the fd and increment the usage count.
				 * Use fget_raw() to allow passing O_PATH fds.
				 */
				if (fd < 0)
					return -EBADF;

				res->fds[i] = fget_raw(fd);
				if (!res->fds[i])
					return -EBADF;

				res->fds_count++;

				ret = kdbus_handle_check_file(res->fds[i]);
				if (ret < 0)
					return ret;
			}

			break;
		}

		case KDBUS_ITEM_BLOOM_FILTER: {
			u64 bloom_size;

			/* do not allow multiple bloom filters */
			if (has_bloom)
				return -EEXIST;
			has_bloom = true;

			bloom_size = payload_size -
				     offsetof(struct kdbus_bloom_filter, data);

			/*
			* Allow only bloom filter sizes of a multiple of 64bit.
			*/
			if (!KDBUS_IS_ALIGNED8(bloom_size))
				return -EFAULT;

			/* do not allow mismatching bloom filter sizes */
			if (bloom_size != bus->bloom.size)
				return -EDOM;

			kmsg->bloom_filter = &item->bloom_filter;
			break;
		}

		case KDBUS_ITEM_DST_NAME:
			/* do not allow multiple names */
			if (has_name)
				return -EEXIST;
			has_name = true;

			if (!kdbus_name_is_valid(item->str, false))
				return -EINVAL;

			res->dst_name = kstrdup(item->str, GFP_KERNEL);
			if (!res->dst_name)
				return -ENOMEM;
			break;

		default:
			return -EINVAL;
		}
	}

	/* name is needed if no ID is given */
	if (msg->dst_id == KDBUS_DST_ID_NAME && !has_name)
		return -EDESTADDRREQ;

	if (is_broadcast) {
		/* Broadcasts can't take names */
		if (has_name)
			return -EBADMSG;

		/* All broadcasts have to be signals */
		if (!is_signal)
			return -EBADMSG;

		/* Timeouts are not allowed for broadcasts */
		if (msg->timeout_ns > 0)
			return -ENOTUNIQ;
	}

	/*
	 * Signal messages require a bloom filter, and bloom filters are
	 * only valid with signals.
	 */
	if (is_signal ^ has_bloom)
		return -EBADMSG;

	return 0;
}

/**
 * kdbus_kmsg_new_from_cmd() - create kernel message from send payload
 * @conn:		Connection
 * @cmd_send:		Payload of KDBUS_CMD_SEND
 *
 * Return: a new kdbus_kmsg on success, ERR_PTR on failure.
 */
struct kdbus_kmsg *kdbus_kmsg_new_from_cmd(struct kdbus_conn *conn,
					   struct kdbus_cmd_send *cmd_send)
{
	struct kdbus_kmsg *m;
	u64 size;
	int ret;

	ret = kdbus_copy_from_user(&size, KDBUS_PTR(cmd_send->msg_address),
				   sizeof(size));
	if (ret < 0)
		return ERR_PTR(ret);

	if (size < sizeof(struct kdbus_msg) || size > KDBUS_MSG_MAX_SIZE)
		return ERR_PTR(-EINVAL);

	m = kmalloc(size + KDBUS_KMSG_HEADER_SIZE, GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	memset(m, 0, KDBUS_KMSG_HEADER_SIZE);
	m->seq = atomic64_inc_return(&conn->ep->bus->domain->last_id);

	m->proc_meta = kdbus_meta_proc_new();
	if (IS_ERR(m->proc_meta)) {
		ret = PTR_ERR(m->proc_meta);
		m->proc_meta = NULL;
		goto exit_free;
	}

	m->conn_meta = kdbus_meta_conn_new();
	if (IS_ERR(m->conn_meta)) {
		ret = PTR_ERR(m->conn_meta);
		m->conn_meta = NULL;
		goto exit_free;
	}

	if (copy_from_user(&m->msg, KDBUS_PTR(cmd_send->msg_address), size)) {
		ret = -EFAULT;
		goto exit_free;
	}

	if (m->msg.size != size) {
		ret = -EINVAL;
		goto exit_free;
	}

	if (m->msg.flags & ~(KDBUS_MSG_EXPECT_REPLY |
			     KDBUS_MSG_NO_AUTO_START |
			     KDBUS_MSG_SIGNAL)) {
		ret = -EINVAL;
		goto exit_free;
	}

	ret = kdbus_items_validate(m->msg.items,
				   KDBUS_ITEMS_SIZE(&m->msg, items));
	if (ret < 0)
		goto exit_free;

	m->res = kdbus_msg_resources_new();
	if (IS_ERR(m->res)) {
		ret = PTR_ERR(m->res);
		m->res = NULL;
		goto exit_free;
	}

	/* do not accept kernel-generated messages */
	if (m->msg.payload_type == KDBUS_PAYLOAD_KERNEL) {
		ret = -EINVAL;
		goto exit_free;
	}

	if (m->msg.flags & KDBUS_MSG_EXPECT_REPLY) {
		/* requests for replies need timeout and cookie */
		if (m->msg.timeout_ns == 0 || m->msg.cookie == 0) {
			ret = -EINVAL;
			goto exit_free;
		}

		/* replies may not be expected for broadcasts */
		if (m->msg.dst_id == KDBUS_DST_ID_BROADCAST) {
			ret = -ENOTUNIQ;
			goto exit_free;
		}

		/* replies may not be expected for signals */
		if (m->msg.flags & KDBUS_MSG_SIGNAL) {
			ret = -EINVAL;
			goto exit_free;
		}
	} else {
		/*
		 * KDBUS_SEND_SYNC_REPLY is only valid together with
		 * KDBUS_MSG_EXPECT_REPLY
		 */
		if (cmd_send->flags & KDBUS_SEND_SYNC_REPLY) {
			ret = -EINVAL;
			goto exit_free;
		}

		/* replies cannot be signals */
		if (m->msg.cookie_reply && (m->msg.flags & KDBUS_MSG_SIGNAL)) {
			ret = -EINVAL;
			goto exit_free;
		}
	}

	ret = kdbus_msg_scan_items(m, conn->ep->bus);
	if (ret < 0)
		goto exit_free;

	/* patch-in the source of this message */
	if (m->msg.src_id > 0 && m->msg.src_id != conn->id) {
		ret = -EINVAL;
		goto exit_free;
	}
	m->msg.src_id = conn->id;

	return m;

exit_free:
	kdbus_kmsg_free(m);
	return ERR_PTR(ret);
}
