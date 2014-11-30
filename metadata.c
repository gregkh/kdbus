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
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "bus.h"
#include "connection.h"
#include "item.h"
#include "metadata.h"
#include "names.h"

/**
 * struct kdbus_meta - metadata buffer
 * @kref:		Reference counter
 * @collected:		Flags for already collected and valid data
 * @seq:		Sequence number passed in at collect time
 * @uid:		Task uid
 * @euid:		Task euid
 * @suid:		Task suid
 * @fsuid:		Task fsuid
 * @gid:		Task gid
 * @egid:		Task egid
 * @sgid:		Task sgid
 * @fsgid:		Task fsgid
 * @conn_description:	Source connection's description
 * @owned_names_items:	Array of items with names owned by the source
 * @owned_names_size:	Number of bytes in @owned_names_items
 * @audit_loginuid:	Audit loginuid
 * @audit_sessionid:	Audio session ID
 * @seclabel:		LSM security label
 * @auxgrps:		Auxiliary groups of the task
 * @n_auxgrps:		Number of auxiliary groups
 * @pid:		Pinned GID
 * @tgid:		Pinned TGID
 * @starttime:		Task starttime
 * @ts_monotonic_ns:	Monotonic timestamp taken at collect time
 * @ts_realtime_ns:	Realtime timestamp taken at collect time
 * @exe:		Task's executable file, pinned
 * @cmdline:		Task's cmdline
 * @cgroup:		Cgroup path
 * @pid_comm:		COMM of the TGID
 * @tid_comm:		COMM of the PID
 * @caps:		Capabilites
 * @user_namespace:	User namespace that was active when @caps were recorded
 * @locked:		Meta object contains faked creds and should not be
 *			augmented.
 *
 * Data in this struct is only written by two functions:
 *
 *	kdbus_meta_collect() and
 *	kdbus_meta_fake()
 *
 * All data is stored is the kernel-view of resources and translated into
 * namespaces when kdbus_meta_export() is called.
 */
struct kdbus_meta {
	struct kref kref;

	u64 collected;

	u64 seq;

	kuid_t uid;
	kuid_t euid;
	kuid_t suid;
	kuid_t fsuid;
	kgid_t gid;
	kgid_t egid;
	kgid_t sgid;
	kgid_t fsgid;

	char *conn_description;
	struct kdbus_item *owned_names_items;
	size_t owned_names_size;

	kuid_t audit_loginuid;
	unsigned int audit_sessionid;

	char *seclabel;

	kgid_t *auxgrps;
	size_t n_auxgrps;

	struct pid *pid;
	struct pid *tgid;
	u64 starttime;

	s64 ts_monotonic_ns;
	s64 ts_realtime_ns;

	struct file *exe;
	char *cmdline;
	char *cgroup;

	char pid_comm[TASK_COMM_LEN];
	char tid_comm[TASK_COMM_LEN];

	struct caps {
		u32 last_cap;
		struct {
			u32 caps[_KERNEL_CAPABILITY_U32S];
		} set[4];
	} caps;

	struct user_namespace *user_namespace;

	bool locked:1;
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

	kref_init(&m->kref);

	return m;
}

static void __kdbus_meta_free(struct kref *kref)
{
	struct kdbus_meta *meta = container_of(kref, struct kdbus_meta, kref);

	if (meta->exe)
		fput(meta->exe);

	put_user_ns(meta->user_namespace);
	put_pid(meta->tgid);
	put_pid(meta->pid);

	kfree(meta->owned_names_items);
	kfree(meta->conn_description);
	kfree(meta->seclabel);
	kfree(meta->auxgrps);
	kfree(meta->cmdline);
	kfree(meta->cgroup);
	kfree(meta);
}

/**
 * kdbus_meta_ref() - ref metadata
 * @meta:		Metadata object
 *
 * Increase the reference count on a given kdbus_meta object
 *
 * Return: NULL
 */
struct kdbus_meta *kdbus_meta_ref(struct kdbus_meta *meta)
{
	if (meta)
		kref_get(&meta->kref);
	return meta;
}

/**
 * kdbus_meta_unref() - unref metadata
 * @meta:		Metadata object
 *
 * When the last reference is dropped, the internal memory is freed.
 *
 * Return: NULL
 */
struct kdbus_meta *kdbus_meta_unref(struct kdbus_meta *meta)
{
	if (meta)
		kref_put(&meta->kref, __kdbus_meta_free);

	return NULL;
}

/**
 * kdbus_meta_fake() - Fill metadata from faked credentials
 * @meta:	Metadata
 * @creds:	Creds to set, may be %NULL
 * @pids:	PIDs to set, may be %NULL
 * @seclabel:	Seclabel to set, may be %NULL
 *
 * This function takes information stored in @creds, @pids and @seclabel and
 * resolves them to kernel-representations, if possible. A call to this function
 * is considered an alternative to calling kdbus_meta_collect(), which derives
 * the same information from the 'current' task.
 *
 * After the information has been recorded, @meta is locked and cannot be
 * augmented with any more information. IOW, kdbus_meta_collect() will become
 * a no-op.
 *
 * Return: 0 on success, negative error number otherwise.
 */
int kdbus_meta_fake(struct kdbus_meta *meta,
		    const struct kdbus_creds *creds,
		    const struct kdbus_pids *pids,
		    const char *seclabel)
{
	if (creds) {
		struct user_namespace *ns = current_user_ns();

		meta->uid	= make_kuid(ns, creds->uid);
		meta->euid	= make_kuid(ns, creds->euid);
		meta->suid	= make_kuid(ns, creds->suid);
		meta->fsuid	= make_kuid(ns, creds->fsuid);

		meta->gid	= make_kgid(ns, creds->gid);
		meta->egid	= make_kgid(ns, creds->egid);
		meta->sgid	= make_kgid(ns, creds->sgid);
		meta->fsgid	= make_kgid(ns, creds->fsgid);

		if ((creds->uid   != (uid_t)-1 && !uid_valid(meta->uid))   ||
		    (creds->euid  != (uid_t)-1 && !uid_valid(meta->euid))  ||
		    (creds->suid  != (uid_t)-1 && !uid_valid(meta->suid))  ||
		    (creds->fsuid != (uid_t)-1 && !uid_valid(meta->fsuid)) ||
		    (creds->gid   != (gid_t)-1 && !gid_valid(meta->gid))   ||
		    (creds->egid  != (gid_t)-1 && !gid_valid(meta->egid))  ||
		    (creds->sgid  != (gid_t)-1 && !gid_valid(meta->sgid))  ||
		    (creds->fsgid != (gid_t)-1 && !gid_valid(meta->fsgid)))
			return -EINVAL;

		meta->collected |= KDBUS_ATTACH_CREDS;
	}

	if (pids) {
		meta->pid = get_pid(find_vpid(pids->tid));
		meta->tgid = get_pid(find_vpid(pids->pid));
		meta->starttime = pids->starttime;
		meta->collected |= KDBUS_ATTACH_PIDS;
	}

	if (seclabel) {
		meta->seclabel = kstrdup(seclabel, GFP_KERNEL);
		if (!meta->seclabel)
			return -ENOMEM;
	}

	meta->locked = true;

	return 0;
}

static inline void kdbus_meta_write_item(struct kdbus_item *item, u64 type,
					 const void *data, size_t len)
{
	item->type = type;
	item->size = KDBUS_ITEM_HEADER_SIZE + len;

	if (data)
		memcpy(item->data, data, len);
}

/**
 * kdbus_meta_collect() - collect metadata from current process
 * @meta:		Metadata object
 * @seq:		Message sequence number
 * @which:		KDBUS_ATTACH_* mask
 *
 * Collect the data specified in @which from the 'current', and store the
 * kernel-view of resources in @meta. Information that has already been
 * collected will not be gathered again.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_meta_collect(struct kdbus_meta *meta,
		       u64 seq, u64 which)
{
	u64 mask;
	int i;

	/*
	 * If our database is pre-filled with faked information, do
	 * not add anything else.
	 */
	if (meta->locked)
		return 0;

	/* which metadata is wanted but not yet collected? */
	mask = which & ~meta->collected;
	if (mask == 0)
		return 0;

	if (mask & KDBUS_ATTACH_TIMESTAMP) {
		struct timespec ts;

		ktime_get_ts(&ts);
		meta->ts_monotonic_ns = timespec_to_ns(&ts);

		ktime_get_real_ts(&ts);
		meta->ts_realtime_ns = timespec_to_ns(&ts);

		meta->seq = seq;

		meta->collected |= KDBUS_ATTACH_TIMESTAMP;
	}

	if (mask & KDBUS_ATTACH_CREDS) {
		meta->uid	= current_uid();
		meta->euid	= current_euid();
		meta->suid	= current_suid();
		meta->fsuid	= current_fsuid();

		meta->gid	= current_gid();
		meta->egid	= current_egid();
		meta->sgid	= current_sgid();
		meta->fsgid	= current_fsgid();

		meta->user_namespace = get_user_ns(current_user_ns());

		meta->collected |= KDBUS_ATTACH_CREDS;
	}

	if (mask & KDBUS_ATTACH_PIDS) {
		meta->pid = get_pid(task_pid(current));
		meta->tgid = get_pid(task_tgid(current));
		meta->starttime = current->start_time,
		meta->collected |= KDBUS_ATTACH_PIDS;
	}

	if (mask & KDBUS_ATTACH_AUXGROUPS) {
		struct group_info *info;

		info = get_current_groups();

		if (info->ngroups > 0) {
			int i;

			meta->auxgrps = kmalloc(info->ngroups * sizeof(kgid_t),
						GFP_KERNEL);
			if (!meta->auxgrps)
				return -ENOMEM;

			for (i = 0; i < info->ngroups; i++)
				meta->auxgrps[i] = GROUP_AT(info, i);

		}

		meta->n_auxgrps = info->ngroups;
		put_group_info(info);

		meta->collected |= KDBUS_ATTACH_AUXGROUPS;
	}

	if (mask & KDBUS_ATTACH_PID_COMM) {
		get_task_comm(meta->pid_comm, current->group_leader);
		meta->collected |= KDBUS_ATTACH_PID_COMM;
	}

	if (mask & KDBUS_ATTACH_TID_COMM) {
		get_task_comm(meta->tid_comm, current);
		meta->collected |= KDBUS_ATTACH_TID_COMM;
	}

	if (mask & KDBUS_ATTACH_EXE) {
		struct mm_struct *mm = get_task_mm(current);

		if (mm) {
			down_read(&mm->mmap_sem);
			meta->exe = get_file(mm->exe_file);
			up_read(&mm->mmap_sem);
			mmput(mm);
		}

		meta->collected |= KDBUS_ATTACH_EXE;
	}

	if (mask & KDBUS_ATTACH_CMDLINE) {
		struct mm_struct *mm = get_task_mm(current);

		if (mm && mm->arg_end) {
			size_t len = mm->arg_end - mm->arg_start;
			const char __user *s;

			s = (const char __user *)mm->arg_start;
			meta->cmdline = strndup_user(s, len);
			if (!meta->cmdline) {
				mmput(mm);
				return -ENOMEM;
			}

			mmput(mm);
		}

		meta->collected |= KDBUS_ATTACH_CMDLINE;
	}

#ifdef CONFIG_CGROUPS
	/* attach the path of the one group hierarchy specified for the bus */
	if (mask & KDBUS_ATTACH_CGROUP) {
		char tmp[256];
		char *s;

		s = task_cgroup_path(current, tmp, sizeof(tmp));
		if (s) {
			meta->cgroup = kstrdup(s, GFP_KERNEL);
			if (!meta->cgroup)
				return -ENOMEM;
		}

		meta->collected |= KDBUS_ATTACH_CGROUP;
	}
#endif

	if (mask & KDBUS_ATTACH_CAPS) {
		const struct cred *c = current_cred();

		meta->caps.last_cap = CAP_LAST_CAP;

		CAP_FOR_EACH_U32(i) {
			meta->caps.set[0].caps[i] = c->cap_inheritable.cap[i];
			meta->caps.set[1].caps[i] = c->cap_permitted.cap[i];
			meta->caps.set[2].caps[i] = c->cap_effective.cap[i];
			meta->caps.set[3].caps[i] = c->cap_bset.cap[i];
		}

		/* clear unused bits */
		for (i = 0; i < 4; i++)
			meta->caps.set[i].caps[CAP_TO_INDEX(CAP_LAST_CAP)] &=
						CAP_LAST_U32_VALID_MASK;

		meta->collected |= KDBUS_ATTACH_CAPS;
	}

#ifdef CONFIG_SECURITY
	if (mask & KDBUS_ATTACH_SECLABEL) {
		u32 sid;
		char *ctx = NULL;
		u32 len;
		int ret;

		security_task_getsecid(current, &sid);
		ret = security_secid_to_secctx(sid, &ctx, &len);
		if (ret == -EOPNOTSUPP) {
			/*
			 * EOPNOTSUPP means no security module is active,
			 * lets skip adding the seclabel then. This effectively
			 * drops the SECLABEL item.
			 */
		} else if (ret < 0) {
			return ret;
		} else {
			meta->seclabel = kstrdup(ctx, GFP_KERNEL);
			security_release_secctx(ctx, len);
			if (!meta->seclabel)
				return -ENOMEM;

			meta->collected |= KDBUS_ATTACH_SECLABEL;
		}
	}
#endif

#ifdef CONFIG_AUDITSYSCALL
	if (mask & KDBUS_ATTACH_AUDIT) {
		meta->audit_loginuid = audit_get_loginuid(current);
		meta->audit_sessionid = audit_get_sessionid(current);
		meta->collected |= KDBUS_ATTACH_AUDIT;
	}
#endif

	return 0;
}

/**
 * kdbus_meta_collect_dst() - collect metadata according to receive flags of
 *			      a destination connection
 * @meta:	metadata object to collect data on
 * @seq:	message sequence number to set on TIMESTAMP items
 * @conn:	destination connection for this metadata
 *
 * This is a convenience helper for kdbus_meta_collect() which takes the mask
 * of attach-flags from the recv-flags of the destination connection.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_meta_collect_dst(struct kdbus_meta *meta, u64 seq,
			   const struct kdbus_conn *conn_dst)
{
	return kdbus_meta_collect(meta, seq,
				  atomic64_read(&conn_dst->attach_flags_recv));
}

/*
 * kdbus_meta_collect_from_src() - collect metadata from source connection
 * @meta:		Metadata object
 * @conn_src:		Connection to get owned names and description from
 * @conn_dst:		Connection to get attach flags from
 *
 * Collect the data specified in @which from @src_conn.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_meta_collect_src(struct kdbus_meta *meta,
			   struct kdbus_conn *conn_src,
			   const struct kdbus_conn *conn_dst)
{
	u64 mask = atomic64_read(&conn_dst->attach_flags_recv);
	int ret;

	if (!conn_src)
		return 0;

	mutex_lock(&conn_src->lock);

	if (mask & KDBUS_ATTACH_NAMES) {
		const struct kdbus_name_entry *e;
		struct kdbus_item *item;

		meta->owned_names_size = 0;

		list_for_each_entry(e, &conn_src->names_list, conn_entry)
			meta->owned_names_size +=
				KDBUS_ITEM_SIZE(strlen(e->name) + 1);

		kfree(meta->owned_names_items);
		meta->owned_names_items =
			kzalloc(meta->owned_names_size, GFP_KERNEL);
		if (!meta->owned_names_items) {
			ret = -ENOMEM;
			goto exit_unlock;
		}

		item = meta->owned_names_items;

		list_for_each_entry(e, &conn_src->names_list, conn_entry) {
			kdbus_meta_write_item(item, KDBUS_ITEM_OWNED_NAME,
					      e->name, strlen(e->name) + 1);
			item = KDBUS_ITEM_NEXT(item);
		}

		meta->collected |= KDBUS_ATTACH_NAMES;
	}

	if ((mask & KDBUS_ATTACH_CONN_DESCRIPTION) && conn_src->description) {
		kfree(meta->conn_description);
		meta->conn_description =
			kstrdup(conn_src->description, GFP_KERNEL);
		if (!meta->conn_description) {
			ret = -ENOMEM;
			goto exit_unlock;
		}

		meta->collected |= KDBUS_ATTACH_CONN_DESCRIPTION;
	}

	ret = 0;

exit_unlock:
	mutex_unlock(&conn_src->lock);
	return ret;
}

/**
 * kdbus_meta_export() - export information from metadata into buffer
 * @meta:	The metadata object
 * @conn_dst:	Connection to translate items for
 * @mask:	Mask of KDBUS_ATTACH_* flags to export
 * @buf:	Pointer to return the allocated buffer
 * @sz:		Pointer to return the buffer size
 *
 * This function exports information from metadata to allocated buffer.
 * Only information that is requested in @mask and that has been collected
 * before is exported.
 *
 * All information will be translated using the namespaces pinned by @conn_dst.
 *
 * Upon success, @buf will point to the newly allocated buffer, and @sz will
 * report the length of that buffer. The caller is obliged to free @buf when no
 * longer needed.
 *
 * Return: 0 on success, nagative error number otherwise.
 */
int kdbus_meta_export(const struct kdbus_meta *meta,
		      struct kdbus_conn *conn_dst,
		      u64 mask, u8 **buf, size_t *sz)
{
	struct user_namespace *user_ns;
	struct pid_namespace *pid_ns;
	struct kdbus_item *item;
	char *exe_pathname = NULL;
	size_t size = 0;
	int ret = 0;
	u8 *p, *tmp;

	tmp = (char *)__get_free_page(GFP_TEMPORARY | __GFP_ZERO);
	if (!tmp)
		return -ENOMEM;

	mask &= meta->collected & kdbus_meta_attach_mask;

	user_ns = conn_dst->user_namespace;
	pid_ns = conn_dst->pid_namespace;

	/*
	 * We currently have no sane way of translating a set of caps
	 * between different user namespaces. Until that changes, we have
	 * to drop such items.
	 */
	if (meta->user_namespace != user_ns)
		mask &= ~KDBUS_ATTACH_CAPS;

	/* First, determine the overall size of all items */

	if (mask & KDBUS_ATTACH_TIMESTAMP)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_timestamp));

	if (mask & KDBUS_ATTACH_CREDS)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_creds));

	if (mask & KDBUS_ATTACH_PIDS)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_pids));

	if (mask & KDBUS_ATTACH_AUXGROUPS)
		size += KDBUS_ITEM_SIZE(meta->n_auxgrps * sizeof(u32));

	if (mask & KDBUS_ATTACH_PID_COMM)
		size += KDBUS_ITEM_SIZE(strlen(meta->pid_comm) + 1);

	if (mask & KDBUS_ATTACH_TID_COMM)
		size += KDBUS_ITEM_SIZE(strlen(meta->tid_comm) + 1);

	if (mask & KDBUS_ATTACH_EXE) {
		struct path p;

		/*
		 * FIXME: We need access to __d_path() so we can write the path
		 * relative to conn->root_path. Once upstream, we need
		 * EXPORT_SYMBOL(__d_path) or an equivalent of d_path() that
		 * takes the root path directly. Until then, we drop this item
		 * if the root-paths differ.
		 */

		get_fs_root(current->fs, &p);
		if (path_equal(&p, &conn_dst->root_path)) {
			exe_pathname = d_path(&meta->exe->f_path, tmp,
					      PAGE_SIZE);
			if (IS_ERR(exe_pathname)) {
				ret = PTR_ERR(exe_pathname);
				goto exit_free;
			}

			size += KDBUS_ITEM_SIZE(strlen(exe_pathname) + 1);
		}
		path_put(&p);
	}

	if (mask & KDBUS_ATTACH_CMDLINE)
		size += KDBUS_ITEM_SIZE(strlen(meta->cmdline) + 1);

	if (mask & KDBUS_ATTACH_CGROUP)
		size += KDBUS_ITEM_SIZE(strlen(meta->cgroup) + 1);

	if (mask & KDBUS_ATTACH_CAPS)
		size += KDBUS_ITEM_SIZE(sizeof(meta->caps));

	if (mask & KDBUS_ATTACH_SECLABEL)
		size += KDBUS_ITEM_SIZE(strlen(meta->seclabel) + 1);

	if (mask & KDBUS_ATTACH_AUDIT)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_audit));

	if (mask & KDBUS_ATTACH_CONN_DESCRIPTION)
		size += KDBUS_ITEM_SIZE(strlen(meta->conn_description) + 1);

	if (mask & KDBUS_ATTACH_NAMES)
		size += meta->owned_names_size;

	/*
	 * Now we know how big our final blog of metadata will be.
	 * Allocate memory and fill in the items.
	 */

	p = kzalloc(size, GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto exit_free;
	}

	item = (struct kdbus_item *) p;

	if (mask & KDBUS_ATTACH_TIMESTAMP) {
		struct kdbus_timestamp ts = {
			.seqnum		= meta->seq,
			.monotonic_ns	= meta->ts_monotonic_ns,
			.realtime_ns	= meta->ts_realtime_ns,
		};

		kdbus_meta_write_item(item, KDBUS_ITEM_TIMESTAMP,
				      &ts, sizeof(ts));
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_CREDS) {
		struct kdbus_creds creds = {
			.uid	= kdbus_from_kuid_keep(user_ns, meta->uid),
			.euid	= kdbus_from_kuid_keep(user_ns, meta->euid),
			.suid	= kdbus_from_kuid_keep(user_ns, meta->suid),
			.fsuid	= kdbus_from_kuid_keep(user_ns, meta->fsuid),
			.gid	= kdbus_from_kgid_keep(user_ns, meta->gid),
			.egid	= kdbus_from_kgid_keep(user_ns, meta->egid),
			.sgid	= kdbus_from_kgid_keep(user_ns, meta->sgid),
			.fsgid	= kdbus_from_kgid_keep(user_ns, meta->fsgid),
		};

		kdbus_meta_write_item(item, KDBUS_ITEM_CREDS,
				      &creds, sizeof(creds));
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_PIDS) {
		struct kdbus_pids pids = {
			.pid = pid_nr_ns(meta->tgid, pid_ns),
			.tid = pid_nr_ns(meta->pid, pid_ns),
		};

		kdbus_meta_write_item(item, KDBUS_ITEM_PIDS,
				      &pids, sizeof(pids));
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_AUXGROUPS) {
		int i;

		kdbus_meta_write_item(item, KDBUS_ITEM_AUXGROUPS,
				      NULL, meta->n_auxgrps * sizeof(u32));

		for (i = 0; i < meta->n_auxgrps; i++)
			item->data32[i] =
				from_kgid_munged(user_ns, meta->auxgrps[i]);

		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_PID_COMM) {
		kdbus_meta_write_item(item, KDBUS_ITEM_PID_COMM,
				      meta->pid_comm,
				      strlen(meta->pid_comm) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_TID_COMM) {
		kdbus_meta_write_item(item, KDBUS_ITEM_TID_COMM,
				      meta->tid_comm,
				      strlen(meta->tid_comm) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if ((mask & KDBUS_ATTACH_EXE) && exe_pathname) {
		kdbus_meta_write_item(item, KDBUS_ITEM_EXE,
				      exe_pathname, strlen(exe_pathname) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_CMDLINE) {
		kdbus_meta_write_item(item, KDBUS_ITEM_CMDLINE,
				      meta->cmdline, strlen(meta->cmdline) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_CGROUP) {
		kdbus_meta_write_item(item, KDBUS_ITEM_CGROUP,
				      meta->cgroup, strlen(meta->cgroup) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_CAPS) {
		kdbus_meta_write_item(item, KDBUS_ITEM_CAPS,
				      &meta->caps, sizeof(meta->caps));
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_SECLABEL) {
		kdbus_meta_write_item(item, KDBUS_ITEM_SECLABEL,
				      meta->seclabel,
				      strlen(meta->seclabel) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_AUDIT) {
		struct kdbus_audit a;

		a.loginuid  = from_kuid(user_ns, meta->audit_loginuid),
		a.sessionid = meta->audit_sessionid,

		kdbus_meta_write_item(item, KDBUS_ITEM_AUDIT, &a, sizeof(a));
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_CONN_DESCRIPTION) {
		kdbus_meta_write_item(item, KDBUS_ITEM_CONN_DESCRIPTION,
				      meta->conn_description,
				      strlen(meta->conn_description) + 1);
		item = KDBUS_ITEM_NEXT(item);
	}

	if (mask & KDBUS_ATTACH_NAMES) {
		memcpy(item, meta->owned_names_items, meta->owned_names_size);
		item = (struct kdbus_item *)
			((u8 *) item + meta->owned_names_size);
	}

	/* sanity check: the buffer should be completely written now */
	WARN_ON((char *) item != (char *) (p + size));

	*sz = size;
	*buf = p;

exit_free:
	free_page((unsigned long) tmp);

	return ret;
}
