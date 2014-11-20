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

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "item.h"
#include "message.h"
#include "metadata.h"
#include "names.h"
#include "pool.h"

/**
 * struct kdbus_meta - metadata buffer
 * @attached:		Flags for already attached data
 * @data:		Allocated buffer
 * @size:		Number of bytes used
 * @allocated_size:	Size of buffer
 *
 * Used to collect and store connection metadata in a pre-compiled
 * buffer containing struct kdbus_item.
 */
struct kdbus_meta {
	u64 attached;
	struct kdbus_item *data;
	size_t size;
	size_t allocated_size;
};

/**
 * kdbus_meta_new() - create new metadata object
 *
 * Return: a new kdbus_meta object on success, ERR_PTR on failure.
 */
struct kdbus_meta *kdbus_meta_new(void)
{
	struct kdbus_meta *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	return m;
}

/**
 * kdbus_meta_dup() - Duplicate a meta object
 *
 * @orig:	The meta object to duplicate
 *
 * Return: a new kdbus_meta object on success, ERR_PTR on failure.
 */
struct kdbus_meta *kdbus_meta_dup(const struct kdbus_meta *orig)
{
	struct kdbus_meta *m;

	BUG_ON(!orig);

	m = kmalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	m->data = kmemdup(orig->data, orig->allocated_size, GFP_KERNEL);
	if (!m->data) {
		kfree(m);
		return ERR_PTR(-ENOMEM);
	}

	m->attached = orig->attached;
	m->allocated_size = orig->allocated_size;
	m->size = orig->size;

	return m;
}

/**
 * kdbus_meta_free() - release metadata
 * @meta:		Metadata object
 */
void kdbus_meta_free(struct kdbus_meta *meta)
{
	if (!meta)
		return;

	kfree(meta->data);
	kfree(meta);
}

static struct kdbus_item *
kdbus_meta_append_item(struct kdbus_meta *meta, u64 type, size_t payload_size)
{
	size_t extra_size = KDBUS_ITEM_SIZE(payload_size);
	struct kdbus_item *item;
	size_t size;

	/* get new metadata buffer, pre-allocate at least 512 bytes */
	if (!meta->data) {
		size = roundup_pow_of_two(256 + extra_size);
		meta->data = kzalloc(size, GFP_KERNEL);
		if (!meta->data)
			return ERR_PTR(-ENOMEM);

		meta->allocated_size = size;
	}

	/* double the pre-allocated buffer size if needed */
	size = meta->size + extra_size;
	if (size > meta->allocated_size) {
		size_t size_diff;
		struct kdbus_item *data;

		size = roundup_pow_of_two(size);
		size_diff = size - meta->allocated_size;
		data = kmalloc(size, GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);

		memcpy(data, meta->data, meta->size);
		memset((u8 *)data + meta->allocated_size, 0, size_diff);

		kfree(meta->data);
		meta->data = data;
		meta->allocated_size = size;
	}

	/* insert new record */
	item = (struct kdbus_item *)((u8 *)meta->data + meta->size);
	item->type = type;
	item->size = KDBUS_ITEM_HEADER_SIZE + payload_size;

	meta->size += extra_size;

	return item;
}

/**
 * kdbus_meta_append_data() - append given raw data to metadata object
 * @meta:		Metadata object
 * @type:		KDBUS_ITEM_* type
 * @data:		pointer to data to copy from. If it is NULL
 *			then just make space in the metadata buffer.
 * @len:		number of bytes to copy
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_meta_append_data(struct kdbus_meta *meta, u64 type,
			   const void *data, size_t len)
{
	struct kdbus_item *item;

	if (len == 0)
		return 0;

	item = kdbus_meta_append_item(meta, type, len);
	if (IS_ERR(item))
		return PTR_ERR(item);

	if (data)
		memcpy(item->data, data, len);

	return 0;
}

static int kdbus_meta_append_str(struct kdbus_meta *meta, u64 type,
				 const char *str)
{
	return kdbus_meta_append_data(meta, type, str, strlen(str) + 1);
}

static int kdbus_meta_append_timestamp(struct kdbus_meta *meta,
				       u64 seq)
{
	struct kdbus_item *item;
	struct timespec ts;

	item = kdbus_meta_append_item(meta, KDBUS_ITEM_TIMESTAMP,
				      sizeof(struct kdbus_timestamp));
	if (IS_ERR(item))
		return PTR_ERR(item);

	if (seq > 0)
		item->timestamp.seqnum = seq;

	ktime_get_ts(&ts);
	item->timestamp.monotonic_ns = timespec_to_ns(&ts);

	ktime_get_real_ts(&ts);
	item->timestamp.realtime_ns = timespec_to_ns(&ts);

	return 0;
}

static int kdbus_meta_append_cred(struct kdbus_meta *meta,
				  const struct kdbus_domain *domain)
{
	struct kdbus_creds creds = {
		.uid = from_kuid_munged(domain->user_namespace, current_uid()),
		.gid = from_kgid_munged(domain->user_namespace, current_gid()),
		.pid = task_pid_nr_ns(current, domain->pid_namespace),
		.tid = task_tgid_nr_ns(current, domain->pid_namespace),
		.starttime = current->start_time,
	};

	return kdbus_meta_append_data(meta, KDBUS_ITEM_CREDS,
				      &creds, sizeof(creds));
}

static int kdbus_meta_append_auxgroups(struct kdbus_meta *meta,
				       const struct kdbus_domain *domain)
{
	struct group_info *info;
	struct kdbus_item *item;
	int i, ret = 0;
	u64 *gid;

	info = get_current_groups();
	item = kdbus_meta_append_item(meta, KDBUS_ITEM_AUXGROUPS,
				      info->ngroups * sizeof(*gid));
	if (IS_ERR(item)) {
		ret = PTR_ERR(item);
		goto exit_put_groups;
	}

	gid = (u64 *) item->data;

	for (i = 0; i < info->ngroups; i++)
		gid[i] = from_kgid_munged(domain->user_namespace,
					  GROUP_AT(info, i));

exit_put_groups:
	put_group_info(info);

	return ret;
}

static int kdbus_meta_append_src_names(struct kdbus_meta *meta,
				       struct kdbus_conn *conn)
{
	struct kdbus_name_entry *e;
	int ret = 0;

	if (!conn)
		return 0;

	mutex_lock(&conn->lock);
	list_for_each_entry(e, &conn->names_list, conn_entry) {
		struct kdbus_item *item;
		size_t len;

		len = strlen(e->name) + 1;
		item = kdbus_meta_append_item(meta, KDBUS_ITEM_OWNED_NAME,
					      sizeof(struct kdbus_name) + len);
		if (IS_ERR(item)) {
			ret = PTR_ERR(item);
			break;
		}

		item->name.flags = e->flags;
		memcpy(item->name.name, e->name, len);
	}
	mutex_unlock(&conn->lock);

	return ret;
}

static int kdbus_meta_append_exe(struct kdbus_meta *meta)
{
	struct mm_struct *mm = get_task_mm(current);
	struct path *exe_path = NULL;
	char *pathname;
	int ret = 0;
	size_t len;
	char *tmp;

	if (!mm)
		return -EFAULT;

	down_read(&mm->mmap_sem);
	if (mm->exe_file) {
		path_get(&mm->exe_file->f_path);
		exe_path = &mm->exe_file->f_path;
	}
	up_read(&mm->mmap_sem);

	if (!exe_path)
		goto exit_mmput;

	tmp = (char *)__get_free_page(GFP_TEMPORARY | __GFP_ZERO);
	if (!tmp) {
		ret = -ENOMEM;
		goto exit_path_put;
	}

	pathname = d_path(exe_path, tmp, PAGE_SIZE);
	if (IS_ERR(pathname)) {
		ret = PTR_ERR(pathname);
		goto exit_free_page;
	}

	len = tmp + PAGE_SIZE - pathname;
	ret = kdbus_meta_append_data(meta, KDBUS_ITEM_EXE, pathname, len);

exit_free_page:
	free_page((unsigned long) tmp);

exit_path_put:
	path_put(exe_path);

exit_mmput:
	mmput(mm);

	return ret;
}

static int kdbus_meta_append_cmdline(struct kdbus_meta *meta)
{
	struct mm_struct *mm;
	int ret = 0;
	size_t len;
	char *tmp;

	tmp = (char *)__get_free_page(GFP_TEMPORARY | __GFP_ZERO);
	if (!tmp)
		return -ENOMEM;

	mm = get_task_mm(current);
	if (!mm) {
		ret = -EFAULT;
		goto exit_free_page;
	}

	if (!mm->arg_end)
		goto exit_mmput;

	len = mm->arg_end - mm->arg_start;
	if (len > PAGE_SIZE)
		len = PAGE_SIZE;

	ret = copy_from_user(tmp, (const char __user *)mm->arg_start, len);
	if (ret < 0)
		goto exit_mmput;

	ret = kdbus_meta_append_data(meta, KDBUS_ITEM_CMDLINE, tmp, len);

exit_mmput:
	mmput(mm);

exit_free_page:
	free_page((unsigned long) tmp);

	return ret;
}

static int kdbus_meta_append_caps(struct kdbus_meta *meta)
{
	struct caps {
		u32 last_cap;
		struct {
			u32 caps[_KERNEL_CAPABILITY_U32S];
		} set[4];
	} caps;
	unsigned int i;
	const struct cred *cred = current_cred();

	caps.last_cap = CAP_LAST_CAP;

	for (i = 0; i < _KERNEL_CAPABILITY_U32S; i++) {
		caps.set[0].caps[i] = cred->cap_inheritable.cap[i];
		caps.set[1].caps[i] = cred->cap_permitted.cap[i];
		caps.set[2].caps[i] = cred->cap_effective.cap[i];
		caps.set[3].caps[i] = cred->cap_bset.cap[i];
	}

	/* clear unused bits */
	for (i = 0; i < 4; i++)
		caps.set[i].caps[CAP_TO_INDEX(CAP_LAST_CAP)] &=
			CAP_TO_MASK(CAP_LAST_CAP + 1) - 1;

	return kdbus_meta_append_data(meta, KDBUS_ITEM_CAPS,
				      &caps, sizeof(caps));
}

#ifdef CONFIG_CGROUPS
static int kdbus_meta_append_cgroup(struct kdbus_meta *meta)
{
	char *buf, *path;
	int ret;

	buf = (char *)__get_free_page(GFP_TEMPORARY | __GFP_ZERO);
	if (!buf)
		return -ENOMEM;

	path = task_cgroup_path(current, buf, PAGE_SIZE);

	if (path)
		ret = kdbus_meta_append_str(meta, KDBUS_ITEM_CGROUP, path);
	else
		ret = -ENAMETOOLONG;

	free_page((unsigned long) buf);

	return ret;
}
#endif

#ifdef CONFIG_AUDITSYSCALL
static int kdbus_meta_append_audit(struct kdbus_meta *meta,
				   const struct kdbus_domain *domain)
{
	struct kdbus_audit audit;

	audit.loginuid = from_kuid_munged(domain->user_namespace,
					  audit_get_loginuid(current));
	audit.sessionid = audit_get_sessionid(current);

	return kdbus_meta_append_data(meta, KDBUS_ITEM_AUDIT,
				      &audit, sizeof(audit));
}
#endif

#ifdef CONFIG_SECURITY
static int kdbus_meta_append_seclabel(struct kdbus_meta *meta)
{
	u32 len, sid;
	char *label;
	int ret;

	security_task_getsecid(current, &sid);
	ret = security_secid_to_secctx(sid, &label, &len);
	if (ret == -EOPNOTSUPP)
		return 0;
	if (ret < 0)
		return ret;

	if (label && len > 0)
		ret = kdbus_meta_append_data(meta, KDBUS_ITEM_SECLABEL,
					     label, len);
	security_release_secctx(label, len);

	return ret;
}
#endif

/**
 * kdbus_meta_append() - collect metadata from current process
 * @meta:		Metadata object
 * @domain:		The domain to use for namespace translations
 * @conn:		Current connection to read names from
 * @seq:		Message sequence number
 * @which:		KDBUS_ATTACH_* flags which typ of data to attach
 *
 * Collect the data specified in flags and allocate or extend
 * the buffer in the metadata object.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_meta_append(struct kdbus_meta *meta,
		      struct kdbus_domain *domain,
		      struct kdbus_conn *conn,
		      u64 seq, u64 which)
{
	int ret;
	u64 mask;

	/* which metadata is wanted but not yet attached? */
	mask = which & ~meta->attached;
	if (mask == 0)
		return 0;

	if (mask & KDBUS_ATTACH_TIMESTAMP) {
		ret = kdbus_meta_append_timestamp(meta, seq);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_TIMESTAMP;
	}

	if (mask & KDBUS_ATTACH_CREDS) {
		ret = kdbus_meta_append_cred(meta, domain);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_CREDS;
	}

	if (mask & KDBUS_ATTACH_AUXGROUPS) {
		ret = kdbus_meta_append_auxgroups(meta, domain);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_AUXGROUPS;
	}

	if (mask & KDBUS_ATTACH_NAMES && conn) {
		ret = kdbus_meta_append_src_names(meta, conn);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_NAMES;
	}

	if (mask & KDBUS_ATTACH_TID_COMM) {
		char comm[TASK_COMM_LEN];

		get_task_comm(comm, current->group_leader);
		ret = kdbus_meta_append_str(meta, KDBUS_ITEM_TID_COMM, comm);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_TID_COMM;
	}

	if (mask & KDBUS_ATTACH_PID_COMM) {
		char comm[TASK_COMM_LEN];

		get_task_comm(comm, current);
		ret = kdbus_meta_append_str(meta, KDBUS_ITEM_PID_COMM, comm);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_PID_COMM;
	}

	if (mask & KDBUS_ATTACH_EXE) {
		ret = kdbus_meta_append_exe(meta);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_EXE;
	}

	if (mask & KDBUS_ATTACH_CMDLINE) {
		ret = kdbus_meta_append_cmdline(meta);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_CMDLINE;
	}

	/* we always return a 4 elements, the element size is 1/4  */
	if (mask & KDBUS_ATTACH_CAPS) {
		ret = kdbus_meta_append_caps(meta);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_CAPS;
	}

#ifdef CONFIG_CGROUPS
	/* attach the path of the one group hierarchy specified for the bus */
	if (mask & KDBUS_ATTACH_CGROUP) {
		ret = kdbus_meta_append_cgroup(meta);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_CGROUP;
	}
#endif

#ifdef CONFIG_AUDITSYSCALL
	if (mask & KDBUS_ATTACH_AUDIT) {
		ret = kdbus_meta_append_audit(meta, domain);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_AUDIT;
	}
#endif

#ifdef CONFIG_SECURITY
	if (mask & KDBUS_ATTACH_SECLABEL) {
		ret = kdbus_meta_append_seclabel(meta);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_SECLABEL;
	}
#endif

	if ((mask & KDBUS_ATTACH_CONN_DESCRIPTION) && conn && conn->name) {
		ret = kdbus_meta_append_str(meta, KDBUS_ITEM_CONN_DESCRIPTION,
					    conn->name);
		if (ret < 0)
			return ret;

		meta->attached |= KDBUS_ATTACH_CONN_DESCRIPTION;
	}

	return 0;
}

static inline u64 kdbus_item_attach_flag(u64 type)
{
	BUG_ON(type < _KDBUS_ITEM_ATTACH_BASE);
	BUG_ON(type >= _KDBUS_ITEM_ATTACH_BASE + 64);
	return 1ULL << (type - _KDBUS_ITEM_ATTACH_BASE);
}

/**
 * kdbus_meta_size() - calculate the size of an excerpt of a metadata db
 * @meta:	The database object containing the metadata
 * @conn_dst:	The connection that is about to receive the data
 * @mask:	Pointer to KDBUS_ATTACH_* bitmask to calculate the size for.
 *		Callers *must* use the same mask for calls to
 *		kdbus_meta_write().
 *
 * Return: the size in bytes the masked data will consume. Data that should
 * not received by @conn_dst will be filtered out.
 */
size_t kdbus_meta_size(const struct kdbus_meta *meta,
		       const struct kdbus_conn *conn_dst,
		       u64 *mask)
{
	struct kdbus_domain *domain = conn_dst->ep->bus->domain;
	const struct kdbus_item *item;
	size_t size = 0;

	/*
	 * We currently don't have a way to translate capability flags between
	 * user namespaces, so let's drop these items in such cases.
	 */
	if (domain->user_namespace != current_user_ns())
		*mask &= ~KDBUS_ATTACH_CAPS;

	/*
	 * If the domain was created with hide_pid enabled, drop all items
	 * except for such not revealing anything about the task.
	 */
	if (domain->pid_namespace->hide_pid)
		*mask &= KDBUS_ATTACH_TIMESTAMP | KDBUS_ATTACH_NAMES |
			 KDBUS_ATTACH_CONN_DESCRIPTION;

	KDBUS_ITEMS_FOREACH(item, meta->data, meta->size)
		if (*mask & kdbus_item_attach_flag(item->type))
			size += KDBUS_ALIGN8(item->size);

	return size;
}

/**
 * kdbus_meta_write() - Write an excerpt of a metadata db to a slice
 * @meta:	The database object containing the metadata
 * @conn_dst:	The connection that is about to receive the data
 * @mask:	KDBUS_ATTACH_* bitmask to calculate the size for
 * @slice:	The slice to copy the data to
 * @off:	The initial offset in the slice to write to
 *
 * Copies some of the metadata's items to @slice, if that the item is
 * suitable for @conn_dst to be received. Otherwise, the item is omitted.
 * Privided the same input parameters, this function will write exactly as
 * many bytes as reported by kdbus_meta_size().
 *
 * Return: 0 on success, negative error number otherwise.
 */
int kdbus_meta_write(const struct kdbus_meta *meta,
		     const struct kdbus_conn *conn_dst, u64 mask,
		     const struct kdbus_pool_slice *slice, size_t off)
{
	const struct kdbus_item *item;
	int ret;

	KDBUS_ITEMS_FOREACH(item, meta->data, meta->size)
		if (mask & kdbus_item_attach_flag(item->type)) {
			ret = kdbus_pool_slice_copy(slice, off, item,
						    KDBUS_ALIGN8(item->size));
			if (ret < 0)
				return ret;

			off += KDBUS_ALIGN8(item->size);
		}

	return 0;
}
