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

	kdbus_fput_files(r->memfds, r->memfds_count);
	kdbus_fput_files(r->fds, r->fds_count);
	kfree(r->dst_name);
	kfree(r->memfds);
	kfree(r->memfd_sizes);
	kfree(r->vecs);
	kfree(r->fds);
	kfree(r);
}

struct kdbus_msg_resources *
kdbus_msg_resources_ref(struct kdbus_msg_resources *r)
{
	if (r)
		kref_get(&r->kref);
	return r;
}

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
	kdbus_msg_resources_unref(kmsg->res);
	kdbus_meta_unref(kmsg->meta);
	kfree(kmsg);
}

/**
 * kdbus_kmsg_new() - allocate message
 * @extra_size:		Additional size to reserve for data
 *
 * Return: new kdbus_kmsg on success, ERR_PTR on failure.
 */
struct kdbus_kmsg *kdbus_kmsg_new(size_t extra_size)
{
	struct kdbus_kmsg *m;
	size_t size;

	size = sizeof(struct kdbus_kmsg) + KDBUS_ITEM_SIZE(extra_size);
	m = kzalloc(size, GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	m->msg.size = size - KDBUS_KMSG_HEADER_SIZE;
	m->msg.items[0].size = KDBUS_ITEM_SIZE(extra_size);

	return m;
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

	if (file->f_op == &kdbus_handle_ep_ops)
		return -EOPNOTSUPP;

	if (!S_ISSOCK(inode->i_mode))
		return 0;

	/* Almost nothing can be done with O_PATHed files */
	if (file->f_mode & FMODE_PATH)
		return 0;

	sock = SOCKET_I(inode);
	if (sock->sk && sock->ops && sock->ops->family == PF_UNIX)
		return -EOPNOTSUPP;

	return 0;
}

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
	unsigned int items_count = 0;
	bool has_bloom = false;
	bool has_name = false;
	bool has_fds = false;

	/*
	 * Iterate the items once in order to get the number of vecs and
	 * memfds, so that we can allocate the arrays.
	 */
	KDBUS_ITEMS_FOREACH(item, msg->items, KDBUS_ITEMS_SIZE(msg, items)) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC:
			res->vecs_count++;
			break;

		case KDBUS_ITEM_PAYLOAD_MEMFD:
			res->memfds_count++;
			break;

		default:
			break;
		}
	}

	if (res->vecs_count > 0) {
		res->vecs = kcalloc(res->vecs_count,
				    sizeof(struct kdbus_msg_vec), GFP_KERNEL);
		if (!res->vecs)
			return -ENOMEM;
	}

	if (res->memfds_count > 0) {
		res->memfds = kcalloc(res->memfds_count,
				      sizeof(struct file *), GFP_KERNEL);
		if (!res->memfds)
			return -ENOMEM;

		res->memfd_sizes = kcalloc(res->memfds_count,
					   sizeof(size_t), GFP_KERNEL);
		if (!res->memfd_sizes)
			return -ENOMEM;

	}

	/* reset values so we can reuse them as counters below */
	res->vecs_size = 0;
	res->vecs_count = 0;
	res->memfds_count = 0;

	KDBUS_ITEMS_FOREACH(item, msg->items, KDBUS_ITEMS_SIZE(msg, items)) {
		size_t payload_size = KDBUS_ITEM_PAYLOAD_SIZE(item);

		if (++items_count > KDBUS_MSG_MAX_ITEMS)
			return -E2BIG;

		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			struct kdbus_msg_vec *v = res->vecs + res->vecs_count;

			if (res->vecs_size + item->vec.size <= res->vecs_size ||
			    res->vecs_size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
				return -EMSGSIZE;

			v->src_addr = KDBUS_PTR(item->vec.address);

			/* \0-bytes records store only the alignment bytes */
			if (v->src_addr) {
				v->size = item->vec.size;
				v->off = res->vecs_size;
			} else {
				v->size = item->vec.size % 8;
				v->off = ~0ULL;
			}

			res->vecs_size += v->size;
			res->vecs_count++;
			break;
		}

		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			int fd = item->memfd.fd;
			int n = res->memfds_count;
			int seals, mask;
			struct file *f;

			/* Verify the fd and increment the usage count */
			if (fd < 0)
				return -EBADF;

			f = fget(fd);
			if (!f)
				return -EBADF;

			res->memfds[n] = f;
			res->memfds_count++;

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

			/*
			 * The specified size in the item cannot be larger
			 * than the backing file.
			 */
			if (item->memfd.size > i_size_read(file_inode(f)))
				return -EBADF;

			res->memfd_sizes[n] = item->memfd.size;

			break;
		}

		case KDBUS_ITEM_FDS: {
			unsigned int i;
			unsigned int fds_count = payload_size / sizeof(int);

			/* do not allow multiple fd arrays */
			if (has_fds)
				return -EEXIST;
			has_fds = true;

			/* do not allow to broadcast file descriptors */
			if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
				return -ENOTUNIQ;

			if (fds_count > KDBUS_MSG_MAX_FDS)
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

			/* bloom filters are only for broadcast messages */
			if (msg->dst_id != KDBUS_DST_ID_BROADCAST)
				return -EBADMSG;

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
		}
	}

	/* name is needed if no ID is given */
	if (msg->dst_id == KDBUS_DST_ID_NAME && !has_name)
		return -EDESTADDRREQ;

	if (msg->dst_id == KDBUS_DST_ID_BROADCAST) {
		/* broadcasts can't take names */
		if (has_name)
			return -EBADMSG;

		/* broadcast messages require a bloom filter */
		if (!has_bloom)
			return -EBADMSG;

		/* timeouts are not allowed for broadcasts */
		if (msg->timeout_ns > 0)
			return -ENOTUNIQ;
	}

	/* bloom filters are for undirected messages only */
	if (has_name && has_bloom)
		return -EBADMSG;

	return 0;
}

/**
 * kdbus_kmsg_new_from_user() - copy message from user memory
 * @conn:		Connection
 * @msg:		User-provided message
 *
 * Return: a new kdbus_kmsg on success, ERR_PTR on failure.
 */
struct kdbus_kmsg *kdbus_kmsg_new_from_user(struct kdbus_conn *conn,
					    struct kdbus_msg __user *msg)
{
	struct kdbus_kmsg *m;
	u64 size, alloc_size;
	int ret;

	if (!KDBUS_IS_ALIGNED8((unsigned long)msg))
		return ERR_PTR(-EFAULT);

	if (kdbus_size_get_user(&size, msg, struct kdbus_msg))
		return ERR_PTR(-EFAULT);

	if (size < sizeof(struct kdbus_msg) || size > KDBUS_MSG_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	alloc_size = size + KDBUS_KMSG_HEADER_SIZE;

	m = kmalloc(alloc_size, GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);
	memset(m, 0, KDBUS_KMSG_HEADER_SIZE);

	if (copy_from_user(&m->msg, msg, size)) {
		ret = -EFAULT;
		goto exit_free;
	}

	m->res = kdbus_msg_resources_new();
	if (IS_ERR(m->res)) {
		ret = PTR_ERR(m->res);
		m->res = NULL;
		goto exit_free;
	}

	m->res->vec_src_valid = true;

	ret = kdbus_items_validate(m->msg.items,
				   KDBUS_ITEMS_SIZE(&m->msg, items));
	if (ret < 0)
		goto exit_free;

	/* do not accept kernel-generated messages */
	if (m->msg.payload_type == KDBUS_PAYLOAD_KERNEL) {
		ret = -EINVAL;
		goto exit_free;
	}

	ret = kdbus_negotiate_flags(&m->msg, msg, struct kdbus_msg,
				    KDBUS_MSG_FLAGS_EXPECT_REPLY |
				    KDBUS_MSG_FLAGS_SYNC_REPLY |
				    KDBUS_MSG_FLAGS_NO_AUTO_START);
	if (ret < 0)
		goto exit_free;

	if (m->msg.flags & KDBUS_MSG_FLAGS_EXPECT_REPLY) {
		/* requests for replies need a timeout */
		if (m->msg.timeout_ns == 0) {
			ret = -EINVAL;
			goto exit_free;
		}

		/* replies may not be expected for broadcasts */
		if (m->msg.dst_id == KDBUS_DST_ID_BROADCAST) {
			ret = -ENOTUNIQ;
			goto exit_free;
		}
	} else {
		/*
		 * KDBUS_MSG_FLAGS_SYNC_REPLY is only valid together with
		 * KDBUS_MSG_FLAGS_EXPECT_REPLY
		 */
		if (m->msg.flags & KDBUS_MSG_FLAGS_SYNC_REPLY) {
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
