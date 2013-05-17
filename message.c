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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/sizes.h>

#include "message.h"
#include "connection.h"
#include "bus.h"
#include "endpoint.h"
#include "policy.h"
#include "names.h"
#include "match.h"

#define KDBUS_KMSG_HEADER_SIZE offsetof(struct kdbus_kmsg, msg)

static void __maybe_unused kdbus_msg_dump(const struct kdbus_msg *msg)
{
	const struct kdbus_item *item;

	pr_info("MSG size=%llu, flags=0x%llx, dst_id=%llu, src_id=%llu, "
		"cookie=0x%llx payload_type=0x%llx, timeout=%llu\n",
		(unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		(unsigned long long) msg->dst_id,
		(unsigned long long) msg->src_id,
		(unsigned long long) msg->cookie,
		(unsigned long long) msg->payload_type,
		(unsigned long long) msg->timeout_ns);

	KDBUS_ITEM_FOREACH(item, msg) {
		switch (item->type) {
		case KDBUS_MSG_PAYLOAD_VEC:
			pr_info("+KDBUS_MSG_PAYLOAD_VEC (%zu bytes) address=%p size=%zu\n",
				(size_t)item->size, KDBUS_PTR(item->vec.address),
				(size_t)item->vec.size);
			break;

		case KDBUS_MSG_PAYLOAD_MEMFD:
			pr_info("+KDBUS_MSG_PAYLOAD_MEMFD (%zu bytes) size=%zu fd=%i\n",
				(size_t)item->size, (size_t)item->memfd.size,
				item->memfd.fd);
			break;

		default:
			pr_info("+UNKNOWN type=%llu (%zu bytes)\n",
				(unsigned long long)item->type,
				(size_t)item->size);
			break;
		}
	}
}

void kdbus_kmsg_free(struct kdbus_kmsg *kmsg)
{
	kfree(kmsg->meta);
	kfree(kmsg);
}

int kdbus_kmsg_new(size_t extra_size, struct kdbus_kmsg **m)
{
	size_t size = sizeof(struct kdbus_kmsg) + KDBUS_ITEM_SIZE(extra_size);
	struct kdbus_kmsg *kmsg;

	kmsg = kzalloc(size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;

	kmsg->msg.size = size - KDBUS_KMSG_HEADER_SIZE;
	kmsg->msg.items[0].size = KDBUS_ITEM_SIZE(extra_size);

	*m = kmsg;
	return 0;
}

static int kdbus_msg_scan_items(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg)
{
	const struct kdbus_msg *msg = &kmsg->msg;
	const struct kdbus_item *item;
	unsigned int items_count = 0;
	bool has_fds = false;
	bool has_name = false;
	bool has_bloom = false;

	KDBUS_ITEM_FOREACH_VALIDATE(item, msg) {
		/* empty items are invalid */
		if (item->size <= KDBUS_ITEM_HEADER_SIZE)
			return -EINVAL;

		if (++items_count > KDBUS_MSG_MAX_ITEMS)
			return -E2BIG;

		switch (item->type) {
		case KDBUS_MSG_PAYLOAD_VEC:
			if (item->size != KDBUS_ITEM_HEADER_SIZE +
					  sizeof(struct kdbus_vec))
				return -EINVAL;

			/* empty payload is invalid */
			if (item->vec.size == 0)
				return -EINVAL;

			kmsg->vecs_size += item->vec.size;
			if (kmsg->vecs_size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
				return -EMSGSIZE;

			kmsg->vecs_count++;
			break;

		case KDBUS_MSG_PAYLOAD_MEMFD:
			if (item->size != KDBUS_ITEM_HEADER_SIZE +
					  sizeof(struct kdbus_memfd))
				return -EINVAL;

			/* do not allow to broadcast file descriptors */
			if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
				return -ENOTUNIQ;

			if (item->memfd.fd < 0)
				return -EBADF;

			/* empty payload is invalid */
			if (item->memfd.size == 0)
				return -EINVAL;

			kmsg->memfds_count++;
			break;

		case KDBUS_MSG_FDS: {
			unsigned int n;

			/* do not allow multiple fd arrays */
			if (has_fds)
				return -EEXIST;
			has_fds = true;

			/* do not allow to broadcast file descriptors */
			if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
				return -ENOTUNIQ;

			n = (item->size - KDBUS_ITEM_HEADER_SIZE) / sizeof(int);
			if (n > KDBUS_MSG_MAX_FDS)
				return -EMFILE;

			kmsg->fds = item->fds;
			kmsg->fds_count = n;
			break;
		}

		case KDBUS_MSG_BLOOM:
			/* do not allow multiple bloom filters */
			if (has_bloom)
				return -EEXIST;
			has_bloom = true;

			/* bloom filters are only for broadcast messages */
			if (msg->dst_id != KDBUS_DST_ID_BROADCAST)
				return -EBADMSG;

			/* allow only bloom sizes of a multiple of 64bit */
			if (!KDBUS_IS_ALIGNED8(item->size - KDBUS_ITEM_HEADER_SIZE))
				return -EFAULT;

			/* do not allow mismatching bloom filter sizes */
			if (item->size - KDBUS_ITEM_HEADER_SIZE != conn->ep->bus->bloom_size)
				return -EDOM;

			kmsg->bloom = item->data64;
			break;

		case KDBUS_MSG_DST_NAME:
			/* do not allow multiple names */
			if (has_name)
				return -EEXIST;
			has_name = true;

			/* enforce NUL-terminated strings */
			if (!kdbus_validate_nul(item->str, item->size - KDBUS_ITEM_HEADER_SIZE))
				return -EINVAL;

			if (!kdbus_name_is_valid(item->str))
				return -EINVAL;

			kmsg->dst_name = item->str;
			break;

		default:
			return -ENOTSUPP;
		}
	}

	/* validate correct padding and size values to match the overall size */
	if ((char *)item - ((char *)msg + msg->size) >= 8)
		return -EINVAL;

	/* name is needed if no ID is given */
	if (msg->dst_id == KDBUS_DST_ID_WELL_KNOWN_NAME && !has_name)
		return -EDESTADDRREQ;

	/* name and ID should not be given at the same time */
	if (msg->dst_id > KDBUS_DST_ID_WELL_KNOWN_NAME &&
	    msg->dst_id < KDBUS_DST_ID_BROADCAST && has_name)
		return -EBADMSG;

	if (msg->dst_id == KDBUS_DST_ID_BROADCAST) {
		/* broadcast messages require a bloom filter */
		if (!has_bloom)
			return -EBADMSG;

		/* timeouts are not allowed for broadcasts */
		if (msg->timeout_ns)
			return -ENOTUNIQ;
	}

	/* bloom filters are for undirected messages only */
	if (has_name && has_bloom)
		return -EBADMSG;

	return 0;
}

int kdbus_kmsg_new_from_user(struct kdbus_conn *conn,
			     struct kdbus_msg __user *msg,
			     struct kdbus_kmsg **m)
{
	struct kdbus_kmsg *kmsg;
	u64 size, alloc_size;
	int ret;

	if (!KDBUS_IS_ALIGNED8((unsigned long)msg))
		return -EFAULT;

	if (kdbus_size_get_user(&size, msg, struct kdbus_msg))
		return -EFAULT;

	if (size < sizeof(struct kdbus_msg) || size > KDBUS_MSG_MAX_SIZE)
		return -EMSGSIZE;

	alloc_size = size + KDBUS_KMSG_HEADER_SIZE;

	kmsg = kmalloc(alloc_size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;
	memset(kmsg, 0, KDBUS_KMSG_HEADER_SIZE);

	if (copy_from_user(&kmsg->msg, msg, size)) {
		ret = -EFAULT;
		goto exit_free;
	}

	/* check validity and gather some values for processing */
	ret = kdbus_msg_scan_items(conn, kmsg);
	if (ret < 0)
		goto exit_free;

	/* patch-in the source of this message */
	kmsg->msg.src_id = conn->id;

	*m = kmsg;
	return 0;

exit_free:
	kdbus_kmsg_free(kmsg);
	return ret;
}

static struct kdbus_item *
kdbus_kmsg_append(struct kdbus_kmsg *kmsg, size_t extra_size)
{
	struct kdbus_item *item;
	size_t size;

	/* get new metadata buffer, pre-allocate at least 512 bytes */
	if (!kmsg->meta) {
		size = roundup_pow_of_two(256 + KDBUS_ALIGN8(extra_size));
		kmsg->meta = kzalloc(size, GFP_KERNEL);
		if (!kmsg->meta)
			return ERR_PTR(-ENOMEM);

		kmsg->meta_allocated_size = size;
	}

	/* double the pre-allocated buffer size if needed */
	size = kmsg->meta_size + KDBUS_ALIGN8(extra_size);
	if (size > kmsg->meta_allocated_size) {
		size_t size_diff;
		struct kdbus_item *meta;

		size = roundup_pow_of_two(size);
		size_diff = size - kmsg->meta_allocated_size;
		pr_debug("%s: grow to size=%zu\n", __func__, size);
		meta = kmalloc(size, GFP_KERNEL);
		if (!meta)
			return ERR_PTR(-ENOMEM);

		memcpy(meta, kmsg->meta, kmsg->meta_size);
		memset((u8 *)meta + kmsg->meta_allocated_size, 0, size_diff);

		kfree(kmsg->meta);
		kmsg->meta = meta;
		kmsg->meta_allocated_size = size;

	}

	/* insert new record */
	item = (struct kdbus_item *)((u8 *)kmsg->meta + kmsg->meta_size);
	kmsg->meta_size += KDBUS_ALIGN8(extra_size);

	return item;
}

int kdbus_kmsg_append_timestamp(struct kdbus_kmsg *kmsg, u64 *now_ns)
{
	struct kdbus_item *item;
	u64 size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_timestamp));
	struct timespec ts;

	item = kdbus_kmsg_append(kmsg, size);
	if (IS_ERR(item))
		return PTR_ERR(item);

	item->type = KDBUS_MSG_TIMESTAMP;
	item->size = size;

	ktime_get_ts(&ts);
	item->timestamp.monotonic_ns = timespec_to_ns(&ts);

	ktime_get_real_ts(&ts);
	item->timestamp.realtime_ns = timespec_to_ns(&ts);

	if (now_ns)
		*now_ns = item->timestamp.monotonic_ns;

	return 0;
}

static int kdbus_kmsg_append_data(struct kdbus_kmsg *kmsg, u64 type,
				  const void *buf, size_t len)
{
	struct kdbus_item *item;
	u64 size;

	if (len == 0)
		return 0;

	size = KDBUS_ITEM_SIZE(len);
	item = kdbus_kmsg_append(kmsg, size);
	if (IS_ERR(item))
		return PTR_ERR(item);

	item->type = type;
	item->size = KDBUS_ITEM_HEADER_SIZE + len;
	memcpy(item->str, buf, len);

	return 0;
}

static int kdbus_kmsg_append_str(struct kdbus_kmsg *kmsg, u64 type,
				 const char *str)
{
	return kdbus_kmsg_append_data(kmsg, type, str, strlen(str) + 1);
}

int kdbus_kmsg_append_src_names(struct kdbus_kmsg *kmsg,
				struct kdbus_conn *conn)
{
	struct kdbus_name_entry *name_entry;
	struct kdbus_item *item;
	u64 pos = 0, size, strsize = 0;
	int ret = 0;

	mutex_lock(&conn->names_lock);
	list_for_each_entry(name_entry, &conn->names_list, conn_entry)
		strsize += strlen(name_entry->name) + 1;

	/* no names? then don't do anything */
	if (strsize == 0)
		goto exit_unlock;

	size = KDBUS_ITEM_SIZE(strsize);
	item = kdbus_kmsg_append(kmsg, size);
	if (IS_ERR(item)) {
		ret = PTR_ERR(item);
		goto exit_unlock;
	}

	item->type = KDBUS_MSG_SRC_NAMES;
	item->size = KDBUS_ITEM_HEADER_SIZE + strsize;

	list_for_each_entry(name_entry, &conn->names_list, conn_entry) {
		strcpy(item->data + pos, name_entry->name);
		pos += strlen(name_entry->name) + 1;
	}

	kmsg->src_names = item->data;
	kmsg->src_names_len = pos;

exit_unlock:
	mutex_unlock(&conn->names_lock);

	return ret;
}

int kdbus_kmsg_append_cred(struct kdbus_kmsg *kmsg,
			   const struct kdbus_creds *creds)
{
	struct kdbus_item *item;
	u64 size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_creds));

	item = kdbus_kmsg_append(kmsg, size);
	if (IS_ERR(item))
		return PTR_ERR(item);

	item->type = KDBUS_MSG_SRC_CREDS;
	item->size = size;
	memcpy(&item->creds, creds, sizeof(*creds));

	return 0;
}

/*
 * FIXME: dirty and unsafe version of:
 *   http://git.kernel.org/cgit/linux/kernel/git/tj/cgroup.git/commit/?h=review-task_cgroup_path_from_hierarchy
 * remove it when the above is upstream.
 */
int task_cgroup_path_from_hierarchy(struct task_struct *task, int hierarchy_id,
				    char *buf, size_t buflen)
{
	struct cg_cgroup_link {
		struct list_head cgrp_link_list;
		struct cgroup *cgrp;
		struct list_head cg_link_list;
		struct css_set *cg;
	};

	struct cgroupfs_root {
		struct super_block *sb;
		unsigned long subsys_mask;
		int hierarchy_id;
	};

	struct cg_cgroup_link *link;
	int ret = -ENOENT;

//	cgroup_lock();
	list_for_each_entry(link, &current->cgroups->cg_links, cg_link_list) {
		struct cgroup* cg = link->cgrp;
		struct cgroupfs_root *root = (struct cgroupfs_root *)cg->root;

		if (root->hierarchy_id != hierarchy_id)
			continue;

		ret = cgroup_path(cg, buf, buflen);
		break;
	}
//	cgroup_unlock();

	return ret;
}

int kdbus_kmsg_append_for_dst(struct kdbus_kmsg *kmsg,
			      struct kdbus_conn *conn_src,
			      struct kdbus_conn *conn_dst)
{
	struct kdbus_bus *bus = conn_dst->ep->bus;
	int ret = 0;

	if (conn_dst->flags & KDBUS_HELLO_ATTACH_COMM) {
		char comm[TASK_COMM_LEN];

		get_task_comm(comm, current->group_leader);
		ret = kdbus_kmsg_append_str(kmsg, KDBUS_MSG_SRC_TID_COMM, comm);
		if (ret < 0)
			return ret;

		get_task_comm(comm, current);
		ret = kdbus_kmsg_append_str(kmsg, KDBUS_MSG_SRC_PID_COMM, comm);
		if (ret < 0)
			return ret;
	}

	if (conn_dst->flags & KDBUS_HELLO_ATTACH_EXE) {
		struct mm_struct *mm = get_task_mm(current);
		struct path *exe_path = NULL;

		if (mm) {
			down_read(&mm->mmap_sem);
			if (mm->exe_file) {
				path_get(&mm->exe_file->f_path);
				exe_path = &mm->exe_file->f_path;
			}
			up_read(&mm->mmap_sem);
			mmput(mm);
		}

		if (exe_path) {
			char *tmp;
			char *pathname;
			size_t len;

			tmp = (char *) __get_free_page(GFP_TEMPORARY | __GFP_ZERO);
			if (!tmp) {
				path_put(exe_path);
				return -ENOMEM;
			}

			pathname = d_path(exe_path, tmp, PAGE_SIZE);
			if (!IS_ERR(pathname)) {
				len = tmp + PAGE_SIZE - pathname;
				ret = kdbus_kmsg_append_data(kmsg, KDBUS_MSG_SRC_EXE,
							     pathname, len);
			}

			free_page((unsigned long) tmp);
			path_put(exe_path);

			if (ret < 0)
				return ret;
		}
	}

	if (conn_dst->flags & KDBUS_HELLO_ATTACH_CMDLINE) {
		struct mm_struct *mm = current->mm;
		char *tmp;

		tmp = (char *) __get_free_page(GFP_TEMPORARY | __GFP_ZERO);
		if (!tmp)
			return -ENOMEM;

		if (mm && mm->arg_end) {
			size_t len = mm->arg_end - mm->arg_start;

			if (len > PAGE_SIZE)
				len = PAGE_SIZE;

			ret = copy_from_user(tmp, (const char __user *) mm->arg_start, len);
			if (ret == 0)
				ret = kdbus_kmsg_append_data(kmsg, KDBUS_MSG_SRC_CMDLINE,
							     tmp, len);
		}

		free_page((unsigned long) tmp);

		if (ret < 0)
			return ret;
	}

	/* we always return a 4 elements, the element size is 1/4  */
	if (conn_dst->flags & KDBUS_HELLO_ATTACH_CAPS) {
		const struct cred *cred;
		struct caps {
			u32 cap[_KERNEL_CAPABILITY_U32S];
		} cap[4];
		unsigned int i;

		rcu_read_lock();
		cred = __task_cred(current);
		for (i = 0; i < _KERNEL_CAPABILITY_U32S; i++) {
			cap[0].cap[i] = cred->cap_inheritable.cap[i];
			cap[1].cap[i] = cred->cap_permitted.cap[i];
			cap[2].cap[i] = cred->cap_effective.cap[i];
			cap[3].cap[i] = cred->cap_bset.cap[i];
		}
		rcu_read_unlock();

		/* clear unused bits */
		for (i = 0; i < 4; i++)
			cap[i].cap[CAP_TO_INDEX(CAP_LAST_CAP)] &=
				CAP_TO_MASK(CAP_LAST_CAP + 1) - 1;

		ret = kdbus_kmsg_append_data(kmsg, KDBUS_MSG_SRC_CAPS,
					     cap, sizeof(cap));
		if (ret < 0)
			return ret;
	}

#ifdef CONFIG_CGROUPS
	/* attach the path of the one group hierarchy specified for the bus */
	if (conn_dst->flags & KDBUS_HELLO_ATTACH_CGROUP && bus->cgroup_id > 0) {
		char *tmp;

		tmp = (char *) __get_free_page(GFP_TEMPORARY | __GFP_ZERO);
		if (!tmp)
			return -ENOMEM;

		ret = task_cgroup_path_from_hierarchy(current, bus->cgroup_id, tmp, PAGE_SIZE);
		if (ret >= 0)
			ret = kdbus_kmsg_append_str(kmsg, KDBUS_MSG_SRC_CGROUP, tmp);

		free_page((unsigned long) tmp);

		if (ret < 0)
			return ret;
	}
#endif

#ifdef CONFIG_AUDITSYSCALL
	if (conn_dst->flags & KDBUS_HELLO_ATTACH_AUDIT) {
		ret = kdbus_kmsg_append_data(kmsg, KDBUS_MSG_SRC_AUDIT,
					     conn_src->audit_ids,
					     sizeof(conn_src->audit_ids));
		if (ret < 0)
			return ret;
	}
#endif

#ifdef CONFIG_SECURITY
	if (conn_dst->flags & KDBUS_HELLO_ATTACH_SECLABEL) {
		if (conn_src->sec_label_len > 0) {
			ret = kdbus_kmsg_append_data(kmsg,
						     KDBUS_MSG_SRC_SECLABEL,
						     conn_src->sec_label,
						     conn_src->sec_label_len);
			if (ret < 0)
				return ret;
		}
	}
#endif

	return 0;
}
