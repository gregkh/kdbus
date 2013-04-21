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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/sizes.h>

#include "message.h"
#include "connection.h"
#include "bus.h"
#include "ep.h"
#include "policy.h"
#include "names.h"
#include "match.h"

#define KDBUS_MSG_HEADER_SIZE offsetof(struct kdbus_msg, items)
#define KDBUS_KMSG_HEADER_SIZE offsetof(struct kdbus_kmsg, msg)

static void kdbus_msg_dump(const struct kdbus_msg *msg);

static void kdbus_kmsg_free(struct kdbus_kmsg *kmsg)
{
	int i;

	if (kmsg->fds) {
		for (i = 0; i < kmsg->fds->count; i++)
			fput(kmsg->fds->fp[i]);
		kfree(kmsg->fds->items);
		kfree(kmsg->fds);
	}

	if (kmsg->payloads) {
		for (i = 0; i < kmsg->payloads->count; i++)
			kfree(kmsg->payloads->items[i]);

		kfree(kmsg->payloads);
	}

	if (kmsg->meta) {
		kdbus_conn_sub_size_allocation(kmsg->conn_src,
					       kmsg->meta->allocated_size);
		kfree(kmsg->meta);
	}

	kfree(kmsg);
}

static void __kdbus_kmsg_free(struct kref *kref)
{
	struct kdbus_kmsg *kmsg = container_of(kref, struct kdbus_kmsg, kref);

	return kdbus_kmsg_free(kmsg);
}

void kdbus_kmsg_unref(struct kdbus_kmsg *kmsg)
{
	kref_put(&kmsg->kref, __kdbus_kmsg_free);
}

static struct kdbus_kmsg *kdbus_kmsg_ref(struct kdbus_kmsg *kmsg)
{
	kref_get(&kmsg->kref);
	return kmsg;
}

int kdbus_kmsg_new(size_t extra_size, struct kdbus_kmsg **m)
{
	size_t size = sizeof(struct kdbus_kmsg) + KDBUS_ITEM_SIZE(extra_size);
	struct kdbus_kmsg *kmsg;

	kmsg = kzalloc(size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;

	kref_init(&kmsg->kref);

	kmsg->msg.size = size - KDBUS_KMSG_HEADER_SIZE;
	kmsg->msg.items[0].size = KDBUS_ITEM_SIZE(extra_size);

	*m = kmsg;
	return 0;
}

static int kdbus_msg_scan_items(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg)
{
	const struct kdbus_msg *msg = &kmsg->msg;
	const struct kdbus_msg_item *item;
	int num_records = 0;
	int num_payloads = 0;
	int num_fds = 0;
	bool has_fds = false;
	bool has_name = false;
	bool has_bloom = false;
	int ret;

	KDBUS_ITEM_FOREACH_VALIDATE(item, msg) {
		/* empty data records are invalid */
		if (item->size <= KDBUS_ITEM_HEADER_SIZE)
			return -EINVAL;

		if (++num_records > 512)
			return -E2BIG;

		switch (item->type) {
		case KDBUS_MSG_PAYLOAD:
			if (item->size > SZ_64K)
				return -EMSGSIZE;
			break;

		case KDBUS_MSG_PAYLOAD_VEC:
			if (item->size != KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec))
				return -EINVAL;
			if (item->vec.size > SZ_64K)
				return -EMSGSIZE;
			num_payloads++;
			break;

		case KDBUS_MSG_UNIX_FDS:
			/* do not allow multiple fd arrays */
			if (has_fds)
				return -EEXIST;
			has_fds = true;

			/* do not allow to broadcast file descriptors */
			if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
				return -ENOTUNIQ;

			num_fds = (item->size - KDBUS_ITEM_HEADER_SIZE) / sizeof(int);
			if (num_fds > 256)
				return -EMFILE;
			break;

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
				return -EINVAL;

			/* do not allow mismatching bloom filter sizes */
			if (item->size - KDBUS_ITEM_HEADER_SIZE != conn->ep->bus->bloom_size)
				return -EDOM;
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
			break;

		default:
			return -ENOTSUPP;
		}
	}

	/* expect correct padding and size values */
	if ((char *)item - ((char *)msg + msg->size) >= 8)
		return -EINVAL;

	/* name is needed for broadcast */
	if (msg->dst_id == KDBUS_DST_ID_WELL_KNOWN_NAME && !has_name)
		return -EDESTADDRREQ;

	/* name and ID should not be given at the same time */
	if (msg->dst_id > KDBUS_DST_ID_WELL_KNOWN_NAME &&
	    msg->dst_id < KDBUS_DST_ID_BROADCAST && has_name)
		return -EBADMSG;

	/* broadcast messages require a bloom filter */
	if (msg->dst_id == KDBUS_DST_ID_BROADCAST && !has_bloom)
		return -EBADMSG;

	/* bloom filters are for undirected messages only */
	if (has_name && has_bloom)
		return -EBADMSG;

	/* allocate array for file descriptors */
	if (has_fds) {
		struct kdbus_fds *fds;
		int i;

		fds = kzalloc(sizeof(struct kdbus_fds) +
			      (num_fds * sizeof(struct file *)), GFP_KERNEL);
		if (!fds) {
			ret = -ENOMEM;
			goto exit_free;
		}

		fds->items = kmalloc(KDBUS_ITEM_HEADER_SIZE +
				(sizeof(int) * num_fds), GFP_KERNEL);
		if (!fds->items) {
			ret = -ENOMEM;
			goto exit_free;
		}

		for (i = 0; i < num_fds; i++)
			fds->items->fds[i] = -1;

		kmsg->fds = fds;
	}

	/* allocate array for payload references */
	if (num_payloads > 256)
		return -E2BIG;

	if (num_payloads > 0) {
		struct kdbus_payload *pls;

		pls = kzalloc(sizeof(struct kdbus_payload) + (num_payloads *
				sizeof(struct kdbus_msg_item *)), GFP_KERNEL);
		if (!pls) {
			ret = -ENOMEM;
			goto exit_free;
		}

		kmsg->payloads = pls;
	}

	return 0;

exit_free:
	kfree(kmsg->fds);
	kfree(kmsg->payloads);

	return ret;
}

/*
 * Copy one data reference into our kmsg payload array; the
 * KDBUS_MSG_PAYLOAD_VEC record is hereby converted into a
 * KDBUS_MSG_PAYLOAD record.
 */
static int kdbus_copy_user_payload(struct kdbus_kmsg *kmsg,
				   const struct kdbus_msg_item *item)
{
	u64 size;
	struct kdbus_msg_item *d;
	void __user *user_addr;

	size = KDBUS_ITEM_HEADER_SIZE + item->vec.size;

	d = kmalloc(size, GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	d->size = size;
	d->type = KDBUS_MSG_PAYLOAD;

	user_addr = (void __user *)item->vec.address;
	if (copy_from_user(&d->data, user_addr, item->vec.size)) {
		kfree(d);
		return -EFAULT;
	}

	kmsg->payloads->items[kmsg->payloads->count++] = d;

	return 0;
}

/*
 * Grab and keep references to passed files descriptors, to install
 * them in the receiving process at message delivery.
 */
static int kdbus_copy_user_fds(struct kdbus_kmsg *kmsg,
			       const struct kdbus_msg_item *item)
{
	int i;
	int count;

	count = (item->size - KDBUS_ITEM_HEADER_SIZE) / sizeof(int);
	for (i = 0; i < count; i++) {
		struct file *fp;

		fp = fget(item->fds[i]);
		if (!fp)
			goto unwind;

		kmsg->fds->fp[kmsg->fds->count++] = fp;
	}

	return 0;

unwind:
	for (i = 0; i < kmsg->fds->count; i++) {
		fput(kmsg->fds->fp[i]);
		kmsg->fds->fp[i] = NULL;
	}

	kmsg->fds->count = 0;
	return -EBADF;
}

/*
 * Check the validity of a message. The general layout of the received message
 * is not altered before it is delivered.
 */
int kdbus_kmsg_new_from_user(struct kdbus_conn *conn, void __user *buf,
			     struct kdbus_kmsg **m)
{
	struct kdbus_kmsg *kmsg;
	const struct kdbus_msg_item *item;
	u64 size, alloc_size;
	int ret;

	if (!KDBUS_IS_ALIGNED8((void __force *)buf))
		return -EFAULT;

	if (kdbus_size_get_user(size, buf, struct kdbus_msg))
		return -EFAULT;

	if (size < sizeof(struct kdbus_msg) || size > KDBUS_CMD_MAXSIZE)
		return -EMSGSIZE;

	alloc_size = size + KDBUS_KMSG_HEADER_SIZE;

	kmsg = kmalloc(alloc_size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;

	memset(kmsg, 0, KDBUS_KMSG_HEADER_SIZE);

	if (copy_from_user(&kmsg->msg, buf, size)) {
		ret = -EFAULT;
		goto exit_free;
	}

	/* check validity and prepare handling of reference data records */
	ret = kdbus_msg_scan_items(conn, kmsg);
	if (ret < 0)
		goto exit_free;

	/* fill in sender ID */
	kmsg->msg.src_id = conn->id;

	/* keep a reference to the source connection, for accounting */
	kmsg->conn_src = conn;

	/*
	 * iterate over the receiced data records and resolve external
	 * references and store them in "struct kmsg"
	 */
	KDBUS_ITEM_FOREACH(item, &kmsg->msg) {
		switch (item->type) {
		case KDBUS_MSG_PAYLOAD_VEC:
			ret = kdbus_copy_user_payload(kmsg, item);
			if (ret < 0)
				goto exit_free;
			break;

		case KDBUS_MSG_UNIX_FDS:
			ret = kdbus_copy_user_fds(kmsg, item);
			if (ret < 0)
				goto exit_free;
			break;
		}
	}

	kref_init(&kmsg->kref);

	*m = kmsg;
	return 0;

exit_free:
	kdbus_kmsg_free(kmsg);
	return ret;
}

const struct kdbus_msg_item *
kdbus_msg_get_item(const struct kdbus_msg *msg, u64 type, int index)
{
	const struct kdbus_msg_item *item;

	KDBUS_ITEM_FOREACH(item, msg)
		if (item->type == type && index-- == 0)
			return item;

	return NULL;
}

static void __maybe_unused kdbus_msg_dump(const struct kdbus_msg *msg)
{
	const struct kdbus_msg_item *item;

	pr_info("msg size=%llu, flags=0x%llx, dst_id=%llu, src_id=%llu, "
		"cookie=0x%llx payload_type=0x%llx, timeout=%llu\n",
		(unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		(unsigned long long) msg->dst_id,
		(unsigned long long) msg->src_id,
		(unsigned long long) msg->cookie,
		(unsigned long long) msg->payload_type,
		(unsigned long long) msg->timeout_ns);

	KDBUS_ITEM_FOREACH(item, msg) {
		pr_info("`- msg_item size=%llu, type=0x%llx\n",
			item->size, item->type);
	}
}

static struct kdbus_msg_item *
kdbus_kmsg_append(struct kdbus_kmsg *kmsg, u64 extra_size)
{
	struct kdbus_msg_item *item;
	u64 size;
	int ret;

	/* get new metadata buffer, pre-allocate at least 512 bytes */
	if (!kmsg->meta) {
		size = roundup_pow_of_two(256 + KDBUS_ALIGN8(extra_size));
		ret = kdbus_conn_add_size_allocation(kmsg->conn_src, size);
		if (ret < 0)
			return ERR_PTR(ret);

		kmsg->meta = kzalloc(size, GFP_KERNEL);
		if (!kmsg->meta)
			return ERR_PTR(-ENOMEM);

		kmsg->meta->size = offsetof(struct kdbus_meta, items);
		kmsg->meta->allocated_size = size;
	}

	/* double the pre-allocated buffer size if needed */
	size = kmsg->meta->size + KDBUS_ALIGN8(extra_size);
	if (size > kmsg->meta->allocated_size) {
		struct kdbus_meta *meta;
		size_t size_diff;

		size = roundup_pow_of_two(size);
		size_diff = size - kmsg->meta->allocated_size;

		ret = kdbus_conn_add_size_allocation(kmsg->conn_src, size_diff);
		if (ret < 0)
			return ERR_PTR(ret);

		pr_info("kdbus_kmsg_append: grow to size=%llu\n", size);
		meta = kmalloc(size, GFP_KERNEL);
		if (!meta)
			return ERR_PTR(-ENOMEM);

		memcpy(meta, kmsg->meta, kmsg->meta->size);
		memset((u8 *)meta + kmsg->meta->allocated_size, 0, size_diff);
		meta->allocated_size = size;

		kfree(kmsg->meta);
		kmsg->meta = meta;
	}

	/* insert new record */
	item = (struct kdbus_msg_item *)((u8 *)kmsg->meta + kmsg->meta->size);
	kmsg->meta->size += KDBUS_ALIGN8(extra_size);

	return item;
}

static int kdbus_kmsg_append_timestamp(struct kdbus_kmsg *kmsg, u64 *now_ns)
{
	struct kdbus_msg_item *item;
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
	struct kdbus_msg_item *item;
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
	u64 len;
	u64 size;
	struct kdbus_msg_item *item;

	len = strlen(str);
	size = KDBUS_ITEM_SIZE(len);
	item = kdbus_kmsg_append(kmsg, size);
	if (IS_ERR(item))
		return PTR_ERR(item);

	item->type = type;
	item->size = KDBUS_ITEM_HEADER_SIZE + len;
	memcpy(item->str, str, len + 1);

	return 0;
}

static int kdbus_kmsg_append_src_names(struct kdbus_kmsg *kmsg,
				       struct kdbus_conn *conn)
{
	struct kdbus_name_entry *name_entry;
	struct kdbus_msg_item *item;
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

exit_unlock:
	mutex_unlock(&conn->names_lock);

	return ret;
}

static int kdbus_kmsg_append_cred(struct kdbus_kmsg *kmsg,
				  const struct kdbus_creds *creds)
{
	struct kdbus_msg_item *item;
	u64 size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_creds));

	item = kdbus_kmsg_append(kmsg, size);
	if (IS_ERR(item))
		return PTR_ERR(item);

	item->type = KDBUS_MSG_SRC_CREDS;
	item->size = size;
	memcpy(&item->creds, creds, sizeof(*creds));

	return 0;
}

static int kdbus_conn_enqueue_kmsg(struct kdbus_conn *conn,
				   struct kdbus_kmsg *kmsg)
{
	struct kdbus_msg_list_entry *entry;
	int ret = 0;

	if (!conn->active)
		return -ENOTCONN;

	if (kmsg->payloads && !(conn->flags & KDBUS_CMD_HELLO_ACCEPT_MMAP))
		return -ECOMM;

	if (kmsg->fds && !(conn->flags & KDBUS_CMD_HELLO_ACCEPT_FD))
		return -ECOMM;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->kmsg = kdbus_kmsg_ref(kmsg);
	INIT_LIST_HEAD(&entry->entry);

	mutex_lock(&conn->msg_lock);
	if (conn->msg_count > KDBUS_CONN_MAX_MSGS) {
		ret = -EOVERFLOW;
	} else {
		list_add_tail(&entry->entry, &conn->msg_list);
		conn->msg_count++;
	}
	mutex_unlock(&conn->msg_lock);

	if (ret == 0)
		wake_up_interruptible(&conn->ep->wait);

	return ret;
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

	cgroup_lock();
	list_for_each_entry(link, &current->cgroups->cg_links, cg_link_list) {
		struct cgroup* cg = link->cgrp;
		struct cgroupfs_root *root = (struct cgroupfs_root *)cg->root;

		if (root->hierarchy_id != hierarchy_id)
			continue;

		ret = cgroup_path(cg, buf, buflen);
		break;
	}
	cgroup_unlock();

	return ret;
}

static int kdbus_msg_append_for_dst(struct kdbus_kmsg *kmsg,
				    struct kdbus_conn *conn_src,
				    struct kdbus_conn *conn_dst)
{
	struct kdbus_bus *bus = conn_dst->ep->bus;
	int ret = 0;

	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_COMM) {
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

	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_EXE) {
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
			int len;

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

	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_CMDLINE) {
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
	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_CAPS) {
		const struct cred *cred;
		struct caps {
			u32 cap[_KERNEL_CAPABILITY_U32S];
		} cap[4];
		int i;

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
	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_CGROUP && bus->cgroup_id > 0) {
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
	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_AUDIT) {
		ret = kdbus_kmsg_append_data(kmsg, KDBUS_MSG_SRC_AUDIT,
					     conn_src->audit_ids,
					     sizeof(conn_src->audit_ids));
		if (ret < 0)
			return ret;
	}
#endif

#ifdef CONFIG_SECURITY
	if (conn_dst->flags & KDBUS_CMD_HELLO_ATTACH_SECLABEL) {
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

int kdbus_kmsg_send(struct kdbus_ep *ep,
		    struct kdbus_conn *conn_src,
		    struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst = NULL;
	const struct kdbus_msg *msg;
	u64 now_ns = 0;
	int ret;

	/* augment incoming message */
	ret = kdbus_kmsg_append_timestamp(kmsg, &now_ns);
	if (ret < 0)
		return ret;

	if (conn_src) {
		ret = kdbus_kmsg_append_src_names(kmsg, conn_src);
		if (ret < 0)
			return ret;

		ret = kdbus_kmsg_append_cred(kmsg, &conn_src->creds);
		if (ret < 0)
			return ret;
	}

	msg = &kmsg->msg;
//	kdbus_msg_dump(msg);

	if (msg->dst_id == KDBUS_DST_ID_WELL_KNOWN_NAME) {
		const struct kdbus_msg_item *name_item;
		const struct kdbus_name_entry *name_entry;

		name_item = kdbus_msg_get_item(msg, KDBUS_MSG_DST_NAME, 0);
		if (!name_item)
			return -EDESTADDRREQ;

		/* lookup and determine conn_dst ... */
		name_entry = kdbus_name_lookup(ep->bus->name_registry,
					       name_item->data);
		if (!name_entry)
			return -ESRCH;

		conn_dst = name_entry->conn;

		if ((msg->flags & KDBUS_MSG_FLAGS_NO_AUTO_START) &&
		    (conn_dst->flags & KDBUS_CMD_HELLO_STARTER))
			return -EADDRNOTAVAIL;

	} else if (msg->dst_id != KDBUS_DST_ID_BROADCAST) {
		/* direct message */
		conn_dst = kdbus_bus_find_conn_by_id(ep->bus, msg->dst_id);
		if (!conn_dst)
			return -ENXIO;
	}

	if (conn_dst) {
		/* direct message */

		if (msg->timeout_ns)
			kmsg->deadline_ns = now_ns + msg->timeout_ns;

		/* check policy */
		if (ep->policy_db && conn_src) {
			ret = kdbus_policy_db_check_send_access(ep->policy_db,
								conn_src,
								conn_dst,
								kmsg->deadline_ns);
			if (ret < 0)
				return ret;
		}

		/* direct message */
		if (conn_src) {
			ret = kdbus_msg_append_for_dst(kmsg, conn_src, conn_dst);
			if (ret < 0)
				return ret;
		}

		ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);

		if (msg->timeout_ns)
			kdbus_conn_schedule_timeout_scan(conn_dst);
	} else {
		/* broadcast */
		/* timeouts are not allowed for broadcasts */
		if (msg->timeout_ns)
			return -ENOTUNIQ;

		ret = 0;

		list_for_each_entry(conn_dst, &ep->connection_list,
				    connection_entry) {
			if (conn_dst->type != KDBUS_CONN_EP)
				continue;

			if (conn_dst->id == msg->src_id)
				continue;

			if (!conn_dst->active)
				continue;

			if (!conn_dst->monitor &&
			    !kdbus_match_db_match_kmsg(conn_dst->match_db,
						       conn_src, conn_dst,
						       kmsg))
				continue;

			ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);
			if (ret < 0)
				break;
		}
	}

	return ret;
}

int kdbus_kmsg_recv(struct kdbus_conn *conn, void __user *buf)
{
	struct kdbus_msg_list_entry *entry;
	const struct kdbus_kmsg *kmsg = NULL;
	const struct kdbus_msg *msg;
	const struct kdbus_msg_item *item;
	u64 size, pos, max_size;
	int payload_ind = 0;
	int ret;

	if (!KDBUS_IS_ALIGNED8((void __force *)buf))
		return -EFAULT;

	if (kdbus_size_get_user(size, buf, struct kdbus_msg))
		return -EFAULT;

	mutex_lock(&conn->msg_lock);
	if (conn->msg_count == 0) {
		ret = -EAGAIN;
		goto exit_unlock;
	}

	entry = list_first_entry(&conn->msg_list, struct kdbus_msg_list_entry, entry);
	kmsg = entry->kmsg;
	msg = &kmsg->msg;

	max_size = msg->size;
	if (kmsg->meta)
		max_size += kmsg->meta->size - offsetof(struct kdbus_meta, items);

	if (kmsg->payloads) {
		int i;

		for (i = 0; i < kmsg->payloads->count; i++)
			max_size += KDBUS_ALIGN8(kmsg->payloads->items[i]->size);
	}

	if (size < max_size) {
		kdbus_size_set_user(max_size, buf, struct kdbus_msg);
		ret = -ENOBUFS;
		goto exit_unlock;
	}

	/* copy the message header */
	if (copy_to_user(buf, msg, KDBUS_MSG_HEADER_SIZE)) {
		ret = -EFAULT;
		goto exit_unlock;
	}

	/* append the data records */
	pos = KDBUS_MSG_HEADER_SIZE;

	KDBUS_ITEM_FOREACH(item, msg) {
		switch (item->type) {
		case KDBUS_MSG_PAYLOAD_VEC: {
			struct kdbus_msg_item *d;

			/* insert data passed-in by reference */
			d = kmsg->payloads->items[payload_ind++];
			if (copy_to_user(buf + pos, d, d->size)) {
				ret = -EFAULT;
				goto exit_unlock;
			}

			pos += KDBUS_ALIGN8(d->size);
			break;
		}

		case KDBUS_MSG_UNIX_FDS:
			/*
			 * Skip the records here, we collected all file
			 * descriptors already when we received them, now
			 * we pass them along in a single data record.
			 */
			break;

		case KDBUS_MSG_DST_NAME:
		case KDBUS_MSG_BLOOM:
			/*
			 * Records passed in by the sender, which are not
			 * interesting for the receiver.
			 */
			break;

		default:
			if (copy_to_user(buf + pos, item, item->size)) {
				ret = -EFAULT;
				goto exit_unlock;
			}

			pos += KDBUS_ALIGN8(item->size);
		}
	}

	/* install file descriptors */
	if (kmsg->fds) {
		int i;
		struct kdbus_msg_item *d;
		size_t size;

		for (i = 0; i < kmsg->fds->count; i++) {
			int fd;

			fd = get_unused_fd();
			if (fd < 0) {
				ret = fd;
				goto exit_unlock_fds;
			}

			fd_install(fd, get_file(kmsg->fds->fp[i]));
			kmsg->fds->items->fds[i] = fd;
		}

		size = KDBUS_ITEM_HEADER_SIZE +
				(sizeof(int) * kmsg->fds->count);
		d = kmsg->fds->items;
		d->size = size;
		d->type = KDBUS_MSG_UNIX_FDS;

		if (copy_to_user(buf + pos, d, size)) {
			ret = -EFAULT;
			goto exit_unlock_fds;
		}

		pos += KDBUS_ALIGN8(size);
	}

	/* append metadata records */
	if (kmsg->meta) {
		if (copy_to_user(buf + pos, kmsg->meta->items,
				 kmsg->meta->size - offsetof(struct kdbus_meta, items))) {
			ret = -EFAULT;
			goto exit_unlock_fds;
		}

		pos += KDBUS_ALIGN8(kmsg->meta->size - offsetof(struct kdbus_meta, items));
	}

	/* update the returned data size in the message header */
	ret = kdbus_size_set_user(pos, buf, struct kdbus_msg);
	if (ret)
		goto exit_unlock_fds;

	conn->msg_count--;
	list_del(&entry->entry);
	kdbus_kmsg_unref(entry->kmsg);
	kfree(entry);
	mutex_unlock(&conn->msg_lock);

	return 0;

exit_unlock_fds:
	/* cleanup installed file descriptors */
	if (kmsg->fds) {
		int i;

		for (i = 0; i < kmsg->fds->count; i++) {
			if (kmsg->fds->items->fds[i] < 0)
				continue;

			fput(kmsg->fds->fp[i]);
			put_unused_fd(kmsg->fds->items->fds[i]);
			kmsg->fds->items->fds[i] = -1;
		}
	}

exit_unlock:
	mutex_unlock(&conn->msg_lock);

	return ret;
}
