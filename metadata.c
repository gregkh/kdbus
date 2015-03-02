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
#include <linux/uidgid.h>
#include <linux/uio.h>
#include <linux/user_namespace.h>
#include <linux/version.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "item.h"
#include "message.h"
#include "metadata.h"
#include "names.h"

/**
 * struct kdbus_meta_proc - Process metadata
 * @kref:		Reference counting
 * @lock:		Object lock
 * @collected:		Bitmask of collected items
 * @valid:		Bitmask of collected and valid items
 * @uid:		UID of process
 * @euid:		EUID of process
 * @suid:		SUID of process
 * @fsuid:		FSUID of process
 * @gid:		GID of process
 * @egid:		EGID of process
 * @sgid:		SGID of process
 * @fsgid:		FSGID of process
 * @pid:		PID of process
 * @tgid:		TGID of process
 * @ppid:		PPID of process
 * @auxgrps:		Auxiliary groups
 * @n_auxgrps:		Number of items in @auxgrps
 * @tid_comm:		TID comm line
 * @pid_comm:		PID comm line
 * @exe_path:		Executable path
 * @root_path:		Root-FS path
 * @cmdline:		Command-line
 * @cgroup:		Full cgroup path
 * @caps:		Capabilities
 * @caps_namespace:	User-namespace of @caps
 * @seclabel:		Seclabel
 * @audit_loginuid:	Audit login-UID
 * @audit_sessionid:	Audit session-ID
 */
struct kdbus_meta_proc {
	struct kref kref;
	struct mutex lock;
	u64 collected;
	u64 valid;

	/* KDBUS_ITEM_CREDS */
	kuid_t uid, euid, suid, fsuid;
	kgid_t gid, egid, sgid, fsgid;

	/* KDBUS_ITEM_PIDS */
	struct pid *pid;
	struct pid *tgid;
	struct pid *ppid;

	/* KDBUS_ITEM_AUXGROUPS */
	kgid_t *auxgrps;
	size_t n_auxgrps;

	/* KDBUS_ITEM_TID_COMM */
	char tid_comm[TASK_COMM_LEN];
	/* KDBUS_ITEM_PID_COMM */
	char pid_comm[TASK_COMM_LEN];

	/* KDBUS_ITEM_EXE */
	struct path exe_path;
	struct path root_path;

	/* KDBUS_ITEM_CMDLINE */
	char *cmdline;

	/* KDBUS_ITEM_CGROUP */
	char *cgroup;

	/* KDBUS_ITEM_CAPS */
	struct caps {
		/* binary compatible to kdbus_caps */
		u32 last_cap;
		struct {
			u32 caps[_KERNEL_CAPABILITY_U32S];
		} set[4];
	} caps;
	struct user_namespace *caps_namespace;

	/* KDBUS_ITEM_SECLABEL */
	char *seclabel;

	/* KDBUS_ITEM_AUDIT */
	kuid_t audit_loginuid;
	unsigned int audit_sessionid;
};

/**
 * struct kdbus_meta_conn
 * @kref:		Reference counting
 * @lock:		Object lock
 * @collected:		Bitmask of collected items
 * @valid:		Bitmask of collected and valid items
 * @ts:			Timestamp values
 * @owned_names_items:	Serialized items for owned names
 * @owned_names_size:	Size of @owned_names_items
 * @conn_description:	Connection description
 */
struct kdbus_meta_conn {
	struct kref kref;
	struct mutex lock;
	u64 collected;
	u64 valid;

	/* KDBUS_ITEM_TIMESTAMP */
	struct kdbus_timestamp ts;

	/* KDBUS_ITEM_OWNED_NAME */
	struct kdbus_item *owned_names_items;
	size_t owned_names_size;

	/* KDBUS_ITEM_CONN_DESCRIPTION */
	char *conn_description;
};

/**
 * kdbus_meta_proc_new() - Create process metadata object
 *
 * Return: Pointer to new object on success, ERR_PTR on failure.
 */
struct kdbus_meta_proc *kdbus_meta_proc_new(void)
{
	struct kdbus_meta_proc *mp;

	mp = kzalloc(sizeof(*mp), GFP_KERNEL);
	if (!mp)
		return ERR_PTR(-ENOMEM);

	kref_init(&mp->kref);
	mutex_init(&mp->lock);

	return mp;
}

static void kdbus_meta_proc_free(struct kref *kref)
{
	struct kdbus_meta_proc *mp = container_of(kref, struct kdbus_meta_proc,
						  kref);

	path_put(&mp->exe_path);
	path_put(&mp->root_path);
	put_user_ns(mp->caps_namespace);
	put_pid(mp->ppid);
	put_pid(mp->tgid);
	put_pid(mp->pid);

	kfree(mp->seclabel);
	kfree(mp->auxgrps);
	kfree(mp->cmdline);
	kfree(mp->cgroup);
	kfree(mp);
}

/**
 * kdbus_meta_proc_ref() - Gain reference
 * @mp:		Process metadata object
 *
 * Return: @mp is returned
 */
struct kdbus_meta_proc *kdbus_meta_proc_ref(struct kdbus_meta_proc *mp)
{
	if (mp)
		kref_get(&mp->kref);
	return mp;
}

/**
 * kdbus_meta_proc_unref() - Drop reference
 * @mp:		Process metadata object
 *
 * Return: NULL
 */
struct kdbus_meta_proc *kdbus_meta_proc_unref(struct kdbus_meta_proc *mp)
{
	if (mp)
		kref_put(&mp->kref, kdbus_meta_proc_free);
	return NULL;
}

static void kdbus_meta_proc_collect_creds(struct kdbus_meta_proc *mp)
{
	mp->uid		= current_uid();
	mp->euid	= current_euid();
	mp->suid	= current_suid();
	mp->fsuid	= current_fsuid();

	mp->gid		= current_gid();
	mp->egid	= current_egid();
	mp->sgid	= current_sgid();
	mp->fsgid	= current_fsgid();

	mp->valid |= KDBUS_ATTACH_CREDS;
}

static void kdbus_meta_proc_collect_pids(struct kdbus_meta_proc *mp)
{
	struct task_struct *parent;

	mp->pid = get_pid(task_pid(current));
	mp->tgid = get_pid(task_tgid(current));

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	mp->ppid = get_pid(task_tgid(parent));
	rcu_read_unlock();

	mp->valid |= KDBUS_ATTACH_PIDS;
}

static int kdbus_meta_proc_collect_auxgroups(struct kdbus_meta_proc *mp)
{
	struct group_info *info;
	size_t i;

	info = get_current_groups();

	if (info->ngroups > 0) {
		mp->auxgrps = kmalloc_array(info->ngroups, sizeof(kgid_t),
					    GFP_KERNEL);
		if (!mp->auxgrps) {
			put_group_info(info);
			return -ENOMEM;
		}

		for (i = 0; i < info->ngroups; i++)
			mp->auxgrps[i] = GROUP_AT(info, i);
	}

	mp->n_auxgrps = info->ngroups;
	put_group_info(info);
	mp->valid |= KDBUS_ATTACH_AUXGROUPS;

	return 0;
}

static void kdbus_meta_proc_collect_tid_comm(struct kdbus_meta_proc *mp)
{
	get_task_comm(mp->tid_comm, current);
	mp->valid |= KDBUS_ATTACH_TID_COMM;
}

static void kdbus_meta_proc_collect_pid_comm(struct kdbus_meta_proc *mp)
{
	get_task_comm(mp->pid_comm, current->group_leader);
	mp->valid |= KDBUS_ATTACH_PID_COMM;
}

static void kdbus_meta_proc_collect_exe(struct kdbus_meta_proc *mp)
{
	struct mm_struct *mm;

	mm = get_task_mm(current);
	if (!mm)
		return;

	down_read(&mm->mmap_sem);
	if (mm->exe_file) {
		mp->exe_path = mm->exe_file->f_path;
		path_get(&mp->exe_path);
		get_fs_root(current->fs, &mp->root_path);
		mp->valid |= KDBUS_ATTACH_EXE;
	}
	up_read(&mm->mmap_sem);

	mmput(mm);
}

static int kdbus_meta_proc_collect_cmdline(struct kdbus_meta_proc *mp)
{
	struct mm_struct *mm;
	char *cmdline;

	mm = get_task_mm(current);
	if (!mm)
		return 0;

	if (!mm->arg_end) {
		mmput(mm);
		return 0;
	}

	cmdline = strndup_user((const char __user *)mm->arg_start,
			       mm->arg_end - mm->arg_start);
	mmput(mm);

	if (IS_ERR(cmdline))
		return PTR_ERR(cmdline);

	mp->cmdline = cmdline;
	mp->valid |= KDBUS_ATTACH_CMDLINE;

	return 0;
}

static int kdbus_meta_proc_collect_cgroup(struct kdbus_meta_proc *mp)
{
#ifdef CONFIG_CGROUPS
	void *page;
	char *s;

	page = (void *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		return -ENOMEM;

	s = task_cgroup_path(current, page, PAGE_SIZE);
	if (s) {
		mp->cgroup = kstrdup(s, GFP_KERNEL);
		if (!mp->cgroup) {
			free_page((unsigned long)page);
			return -ENOMEM;
		}
	}

	free_page((unsigned long)page);
	mp->valid |= KDBUS_ATTACH_CGROUP;
#endif

	return 0;
}

static void kdbus_meta_proc_collect_caps(struct kdbus_meta_proc *mp)
{
	const struct cred *c = current_cred();
	int i;

	/* ABI: "last_cap" equals /proc/sys/kernel/cap_last_cap */
	mp->caps.last_cap = CAP_LAST_CAP;
	mp->caps_namespace = get_user_ns(current_user_ns());

	CAP_FOR_EACH_U32(i) {
		mp->caps.set[0].caps[i] = c->cap_inheritable.cap[i];
		mp->caps.set[1].caps[i] = c->cap_permitted.cap[i];
		mp->caps.set[2].caps[i] = c->cap_effective.cap[i];
		mp->caps.set[3].caps[i] = c->cap_bset.cap[i];
	}

	/* clear unused bits */
	for (i = 0; i < 4; i++)
		mp->caps.set[i].caps[CAP_TO_INDEX(CAP_LAST_CAP)] &=
						CAP_LAST_U32_VALID_MASK;

	mp->valid |= KDBUS_ATTACH_CAPS;
}

static int kdbus_meta_proc_collect_seclabel(struct kdbus_meta_proc *mp)
{
#ifdef CONFIG_SECURITY
	char *ctx = NULL;
	u32 sid, len;
	int ret;

	security_task_getsecid(current, &sid);
	ret = security_secid_to_secctx(sid, &ctx, &len);
	if (ret < 0) {
		/*
		 * EOPNOTSUPP means no security module is active,
		 * lets skip adding the seclabel then. This effectively
		 * drops the SECLABEL item.
		 */
		return (ret == -EOPNOTSUPP) ? 0 : ret;
	}

	mp->seclabel = kstrdup(ctx, GFP_KERNEL);
	security_release_secctx(ctx, len);
	if (!mp->seclabel)
		return -ENOMEM;

	mp->valid |= KDBUS_ATTACH_SECLABEL;
#endif

	return 0;
}

static void kdbus_meta_proc_collect_audit(struct kdbus_meta_proc *mp)
{
#ifdef CONFIG_AUDITSYSCALL
	mp->audit_loginuid = audit_get_loginuid(current);
	mp->audit_sessionid = audit_get_sessionid(current);
	mp->valid |= KDBUS_ATTACH_AUDIT;
#endif
}

/**
 * kdbus_meta_proc_collect() - Collect process metadata
 * @mp:		Process metadata object
 * @what:	Attach flags to collect
 *
 * This collects process metadata from current and saves it in @mp.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_meta_proc_collect(struct kdbus_meta_proc *mp, u64 what)
{
	int ret;

	if (!mp || !(what & (KDBUS_ATTACH_CREDS |
			     KDBUS_ATTACH_PIDS |
			     KDBUS_ATTACH_AUXGROUPS |
			     KDBUS_ATTACH_TID_COMM |
			     KDBUS_ATTACH_PID_COMM |
			     KDBUS_ATTACH_EXE |
			     KDBUS_ATTACH_CMDLINE |
			     KDBUS_ATTACH_CGROUP |
			     KDBUS_ATTACH_CAPS |
			     KDBUS_ATTACH_SECLABEL |
			     KDBUS_ATTACH_AUDIT)))
		return 0;

	mutex_lock(&mp->lock);

	if ((what & KDBUS_ATTACH_CREDS) &&
	    !(mp->collected & KDBUS_ATTACH_CREDS)) {
		kdbus_meta_proc_collect_creds(mp);
		mp->collected |= KDBUS_ATTACH_CREDS;
	}

	if ((what & KDBUS_ATTACH_PIDS) &&
	    !(mp->collected & KDBUS_ATTACH_PIDS)) {
		kdbus_meta_proc_collect_pids(mp);
		mp->collected |= KDBUS_ATTACH_PIDS;
	}

	if ((what & KDBUS_ATTACH_AUXGROUPS) &&
	    !(mp->collected & KDBUS_ATTACH_AUXGROUPS)) {
		ret = kdbus_meta_proc_collect_auxgroups(mp);
		if (ret < 0)
			goto exit_unlock;
		mp->collected |= KDBUS_ATTACH_AUXGROUPS;
	}

	if ((what & KDBUS_ATTACH_TID_COMM) &&
	    !(mp->collected & KDBUS_ATTACH_TID_COMM)) {
		kdbus_meta_proc_collect_tid_comm(mp);
		mp->collected |= KDBUS_ATTACH_TID_COMM;
	}

	if ((what & KDBUS_ATTACH_PID_COMM) &&
	    !(mp->collected & KDBUS_ATTACH_PID_COMM)) {
		kdbus_meta_proc_collect_pid_comm(mp);
		mp->collected |= KDBUS_ATTACH_PID_COMM;
	}

	if ((what & KDBUS_ATTACH_EXE) &&
	    !(mp->collected & KDBUS_ATTACH_EXE)) {
		kdbus_meta_proc_collect_exe(mp);
		mp->collected |= KDBUS_ATTACH_EXE;
	}

	if ((what & KDBUS_ATTACH_CMDLINE) &&
	    !(mp->collected & KDBUS_ATTACH_CMDLINE)) {
		ret = kdbus_meta_proc_collect_cmdline(mp);
		if (ret < 0)
			goto exit_unlock;
		mp->collected |= KDBUS_ATTACH_CMDLINE;
	}

	if ((what & KDBUS_ATTACH_CGROUP) &&
	    !(mp->collected & KDBUS_ATTACH_CGROUP)) {
		ret = kdbus_meta_proc_collect_cgroup(mp);
		if (ret < 0)
			goto exit_unlock;
		mp->collected |= KDBUS_ATTACH_CGROUP;
	}

	if ((what & KDBUS_ATTACH_CAPS) &&
	    !(mp->collected & KDBUS_ATTACH_CAPS)) {
		kdbus_meta_proc_collect_caps(mp);
		mp->collected |= KDBUS_ATTACH_CAPS;
	}

	if ((what & KDBUS_ATTACH_SECLABEL) &&
	    !(mp->collected & KDBUS_ATTACH_SECLABEL)) {
		ret = kdbus_meta_proc_collect_seclabel(mp);
		if (ret < 0)
			goto exit_unlock;
		mp->collected |= KDBUS_ATTACH_SECLABEL;
	}

	if ((what & KDBUS_ATTACH_AUDIT) &&
	    !(mp->collected & KDBUS_ATTACH_AUDIT)) {
		kdbus_meta_proc_collect_audit(mp);
		mp->collected |= KDBUS_ATTACH_AUDIT;
	}

	ret = 0;

exit_unlock:
	mutex_unlock(&mp->lock);
	return ret;
}

/**
 * kdbus_meta_proc_fake() - Fill process metadata from faked credentials
 * @mp:		Metadata
 * @creds:	Creds to set, may be %NULL
 * @pids:	PIDs to set, may be %NULL
 * @seclabel:	Seclabel to set, may be %NULL
 *
 * This function takes information stored in @creds, @pids and @seclabel and
 * resolves them to kernel-representations, if possible. A call to this function
 * is considered an alternative to calling kdbus_meta_add_current(), which
 * derives the same information from the 'current' task.
 *
 * This call uses the current task's namespaces to resolve the given
 * information.
 *
 * Return: 0 on success, negative error number otherwise.
 */
int kdbus_meta_proc_fake(struct kdbus_meta_proc *mp,
			 const struct kdbus_creds *creds,
			 const struct kdbus_pids *pids,
			 const char *seclabel)
{
	int ret;

	if (!mp)
		return 0;

	mutex_lock(&mp->lock);

	if (creds && !(mp->collected & KDBUS_ATTACH_CREDS)) {
		struct user_namespace *ns = current_user_ns();

		mp->uid		= make_kuid(ns, creds->uid);
		mp->euid	= make_kuid(ns, creds->euid);
		mp->suid	= make_kuid(ns, creds->suid);
		mp->fsuid	= make_kuid(ns, creds->fsuid);

		mp->gid		= make_kgid(ns, creds->gid);
		mp->egid	= make_kgid(ns, creds->egid);
		mp->sgid	= make_kgid(ns, creds->sgid);
		mp->fsgid	= make_kgid(ns, creds->fsgid);

		if ((creds->uid   != (uid_t)-1 && !uid_valid(mp->uid))   ||
		    (creds->euid  != (uid_t)-1 && !uid_valid(mp->euid))  ||
		    (creds->suid  != (uid_t)-1 && !uid_valid(mp->suid))  ||
		    (creds->fsuid != (uid_t)-1 && !uid_valid(mp->fsuid)) ||
		    (creds->gid   != (gid_t)-1 && !gid_valid(mp->gid))   ||
		    (creds->egid  != (gid_t)-1 && !gid_valid(mp->egid))  ||
		    (creds->sgid  != (gid_t)-1 && !gid_valid(mp->sgid))  ||
		    (creds->fsgid != (gid_t)-1 && !gid_valid(mp->fsgid))) {
			ret = -EINVAL;
			goto exit_unlock;
		}

		mp->valid |= KDBUS_ATTACH_CREDS;
		mp->collected |= KDBUS_ATTACH_CREDS;
	}

	if (pids && !(mp->collected & KDBUS_ATTACH_PIDS)) {
		mp->pid = get_pid(find_vpid(pids->tid));
		mp->tgid = get_pid(find_vpid(pids->pid));
		mp->ppid = get_pid(find_vpid(pids->ppid));

		if ((pids->tid != 0 && !mp->pid) ||
		    (pids->pid != 0 && !mp->tgid) ||
		    (pids->ppid != 0 && !mp->ppid)) {
			put_pid(mp->pid);
			put_pid(mp->tgid);
			put_pid(mp->ppid);
			mp->pid = NULL;
			mp->tgid = NULL;
			mp->ppid = NULL;
			ret = -EINVAL;
			goto exit_unlock;
		}

		mp->valid |= KDBUS_ATTACH_PIDS;
		mp->collected |= KDBUS_ATTACH_PIDS;
	}

	if (seclabel && !(mp->collected & KDBUS_ATTACH_SECLABEL)) {
		mp->seclabel = kstrdup(seclabel, GFP_KERNEL);
		if (!mp->seclabel) {
			ret = -ENOMEM;
			goto exit_unlock;
		}

		mp->valid |= KDBUS_ATTACH_SECLABEL;
		mp->collected |= KDBUS_ATTACH_SECLABEL;
	}

	ret = 0;

exit_unlock:
	mutex_unlock(&mp->lock);
	return ret;
}

/**
 * kdbus_meta_conn_new() - Create connection metadata object
 *
 * Return: Pointer to new object on success, ERR_PTR on failure.
 */
struct kdbus_meta_conn *kdbus_meta_conn_new(void)
{
	struct kdbus_meta_conn *mc;

	mc = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc)
		return ERR_PTR(-ENOMEM);

	kref_init(&mc->kref);
	mutex_init(&mc->lock);

	return mc;
}

static void kdbus_meta_conn_free(struct kref *kref)
{
	struct kdbus_meta_conn *mc =
		container_of(kref, struct kdbus_meta_conn, kref);

	kfree(mc->conn_description);
	kfree(mc->owned_names_items);
	kfree(mc);
}

/**
 * kdbus_meta_conn_ref() - Gain reference
 * @mc:		Connection metadata object
 */
struct kdbus_meta_conn *kdbus_meta_conn_ref(struct kdbus_meta_conn *mc)
{
	if (mc)
		kref_get(&mc->kref);
	return mc;
}

/**
 * kdbus_meta_conn_unref() - Drop reference
 * @mc:		Connection metadata object
 */
struct kdbus_meta_conn *kdbus_meta_conn_unref(struct kdbus_meta_conn *mc)
{
	if (mc)
		kref_put(&mc->kref, kdbus_meta_conn_free);
	return NULL;
}

static void kdbus_meta_conn_collect_timestamp(struct kdbus_meta_conn *mc,
					      struct kdbus_kmsg *kmsg)
{
	struct timespec ts;

	ktime_get_ts(&ts);
	mc->ts.monotonic_ns = timespec_to_ns(&ts);

	ktime_get_real_ts(&ts);
	mc->ts.realtime_ns = timespec_to_ns(&ts);

	if (kmsg)
		mc->ts.seqnum = kmsg->seq;

	mc->valid |= KDBUS_ATTACH_TIMESTAMP;
}

static int kdbus_meta_conn_collect_names(struct kdbus_meta_conn *mc,
					 struct kdbus_conn *conn)
{
	const struct kdbus_name_entry *e;
	struct kdbus_item *item;
	size_t slen, size;

	lockdep_assert_held(&conn->ep->bus->name_registry->rwlock);

	size = 0;
	list_for_each_entry(e, &conn->names_list, conn_entry)
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_name) +
					strlen(e->name) + 1);

	if (!size)
		return 0;

	item = kmalloc(size, GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	mc->owned_names_items = item;
	mc->owned_names_size = size;

	list_for_each_entry(e, &conn->names_list, conn_entry) {
		slen = strlen(e->name) + 1;
		kdbus_item_set(item, KDBUS_ITEM_OWNED_NAME, NULL,
			       sizeof(struct kdbus_name) + slen);
		item->name.flags = e->flags;
		memcpy(item->name.name, e->name, slen);
		item = KDBUS_ITEM_NEXT(item);
	}

	/* sanity check: the buffer should be completely written now */
	WARN_ON((u8 *)item != (u8 *)mc->owned_names_items + size);

	mc->valid |= KDBUS_ATTACH_NAMES;
	return 0;
}

static int kdbus_meta_conn_collect_description(struct kdbus_meta_conn *mc,
					       struct kdbus_conn *conn)
{
	if (!conn->description)
		return 0;

	mc->conn_description = kstrdup(conn->description, GFP_KERNEL);
	if (!mc->conn_description)
		return -ENOMEM;

	mc->valid |= KDBUS_ATTACH_CONN_DESCRIPTION;
	return 0;
}

/**
 * kdbus_meta_conn_collect() - Collect connection metadata
 * @mc:		Message metadata object
 * @kmsg:	Kmsg to collect data from
 * @conn:	Connection to collect data from
 * @what:	Attach flags to collect
 *
 * This collects connection metadata from @kmsg and @conn and saves it in @mc.
 *
 * If KDBUS_ATTACH_NAMES is set in @what and @conn is non-NULL, the caller must
 * hold the name-registry read-lock of conn->ep->bus->registry.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_meta_conn_collect(struct kdbus_meta_conn *mc,
			    struct kdbus_kmsg *kmsg,
			    struct kdbus_conn *conn,
			    u64 what)
{
	int ret;

	if (!mc || !(what & (KDBUS_ATTACH_TIMESTAMP |
			     KDBUS_ATTACH_NAMES |
			     KDBUS_ATTACH_CONN_DESCRIPTION)))
		return 0;

	mutex_lock(&mc->lock);

	if (kmsg && (what & KDBUS_ATTACH_TIMESTAMP) &&
	    !(mc->collected & KDBUS_ATTACH_TIMESTAMP)) {
		kdbus_meta_conn_collect_timestamp(mc, kmsg);
		mc->collected |= KDBUS_ATTACH_TIMESTAMP;
	}

	if (conn && (what & KDBUS_ATTACH_NAMES) &&
	    !(mc->collected & KDBUS_ATTACH_NAMES)) {
		ret = kdbus_meta_conn_collect_names(mc, conn);
		if (ret < 0)
			goto exit_unlock;
		mc->collected |= KDBUS_ATTACH_NAMES;
	}

	if (conn && (what & KDBUS_ATTACH_CONN_DESCRIPTION) &&
	    !(mc->collected & KDBUS_ATTACH_CONN_DESCRIPTION)) {
		ret = kdbus_meta_conn_collect_description(mc, conn);
		if (ret < 0)
			goto exit_unlock;
		mc->collected |= KDBUS_ATTACH_CONN_DESCRIPTION;
	}

	ret = 0;

exit_unlock:
	mutex_unlock(&mc->lock);
	return ret;
}

/*
 * kdbus_meta_export_prepare() - Prepare metadata for export
 * @mp:		Process metadata, or NULL
 * @mc:		Connection metadata, or NULL
 * @mask:	Pointer to mask of KDBUS_ATTACH_* flags to export
 * @sz:		Pointer to return the size needed by the metadata
 *
 * Does a conservative calculation of how much space metadata information
 * will take up during export. It is 'conservative' because for string
 * translations in namespaces, it will use the kernel namespaces, which is
 * the longest possible version.
 *
 * The actual size consumed by kdbus_meta_export() may hence vary from the
 * one reported here, but it is guaranteed never to be greater.
 *
 * Return: 0 on success, negative error number otherwise.
 */
int kdbus_meta_export_prepare(struct kdbus_meta_proc *mp,
			      struct kdbus_meta_conn *mc,
			      u64 *mask, size_t *sz)
{
	char *exe_pathname = NULL;
	void *exe_page = NULL;
	size_t size = 0;
	u64 valid = 0;
	int ret = 0;

	if (mp) {
		mutex_lock(&mp->lock);
		valid |= mp->valid;
		mutex_unlock(&mp->lock);
	}

	if (mc) {
		mutex_lock(&mc->lock);
		valid |= mc->valid;
		mutex_unlock(&mc->lock);
	}

	*mask &= valid;
	*mask &= kdbus_meta_attach_mask;

	if (!*mask)
		goto exit;

	/* process metadata */

	if (mp && (*mask & KDBUS_ATTACH_CREDS))
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_creds));

	if (mp && (*mask & KDBUS_ATTACH_PIDS))
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_pids));

	if (mp && (*mask & KDBUS_ATTACH_AUXGROUPS))
		size += KDBUS_ITEM_SIZE(mp->n_auxgrps * sizeof(u64));

	if (mp && (*mask & KDBUS_ATTACH_TID_COMM))
		size += KDBUS_ITEM_SIZE(strlen(mp->tid_comm) + 1);

	if (mp && (*mask & KDBUS_ATTACH_PID_COMM))
		size += KDBUS_ITEM_SIZE(strlen(mp->pid_comm) + 1);

	if (mp && (*mask & KDBUS_ATTACH_EXE)) {
		exe_page = (void *)__get_free_page(GFP_TEMPORARY);
		if (!exe_page) {
			ret = -ENOMEM;
			goto exit;
		}

		exe_pathname = d_path(&mp->exe_path, exe_page, PAGE_SIZE);
		if (IS_ERR(exe_pathname)) {
			ret = PTR_ERR(exe_pathname);
			goto exit;
		}

		size += KDBUS_ITEM_SIZE(strlen(exe_pathname) + 1);
		free_page((unsigned long)exe_page);
	}

	if (mp && (*mask & KDBUS_ATTACH_CMDLINE))
		size += KDBUS_ITEM_SIZE(strlen(mp->cmdline) + 1);

	if (mp && (*mask & KDBUS_ATTACH_CGROUP))
		size += KDBUS_ITEM_SIZE(strlen(mp->cgroup) + 1);

	if (mp && (*mask & KDBUS_ATTACH_CAPS))
		size += KDBUS_ITEM_SIZE(sizeof(mp->caps));

	if (mp && (*mask & KDBUS_ATTACH_SECLABEL))
		size += KDBUS_ITEM_SIZE(strlen(mp->seclabel) + 1);

	if (mp && (*mask & KDBUS_ATTACH_AUDIT))
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_audit));

	/* connection metadata */

	if (mc && (*mask & KDBUS_ATTACH_NAMES))
		size += mc->owned_names_size;

	if (mc && (*mask & KDBUS_ATTACH_CONN_DESCRIPTION))
		size += KDBUS_ITEM_SIZE(strlen(mc->conn_description) + 1);

	if (mc && (*mask & KDBUS_ATTACH_TIMESTAMP))
		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_timestamp));

exit:
	*sz = size;

	return ret;
}

static int kdbus_meta_push_kvec(struct kvec *kvec,
				struct kdbus_item_header *hdr,
				u64 type, void *payload,
				size_t payload_size, u64 *size)
{
	hdr->type = type;
	hdr->size = KDBUS_ITEM_HEADER_SIZE + payload_size;
	kdbus_kvec_set(kvec++, hdr, sizeof(*hdr), size);
	kdbus_kvec_set(kvec++, payload, payload_size, size);
	return 2 + !!kdbus_kvec_pad(kvec++, size);
}

/* This is equivalent to from_kuid_munged(), but maps INVALID_UID to itself */
static uid_t kdbus_from_kuid_keep(kuid_t uid)
{
	return uid_valid(uid) ?
		from_kuid_munged(current_user_ns(), uid) : ((uid_t)-1);
}

/* This is equivalent to from_kgid_munged(), but maps INVALID_GID to itself */
static gid_t kdbus_from_kgid_keep(kgid_t gid)
{
	return gid_valid(gid) ?
		from_kgid_munged(current_user_ns(), gid) : ((gid_t)-1);
}

/**
 * kdbus_meta_export() - export information from metadata into a slice
 * @mp:		Process metadata, or NULL
 * @mc:		Connection metadata, or NULL
 * @mask:	Mask of KDBUS_ATTACH_* flags to export
 * @slice:	The slice to export to
 * @offset:	The offset inside @slice to write to
 * @real_size:	The real size the metadata consumed
 *
 * This function exports information from metadata into @slice at offset
 * @offset inside that slice. Only information that is requested in @mask
 * and that has been collected before is exported.
 *
 * In order to make sure not to write out of bounds, @mask must be the same
 * value that was previously returned from kdbus_meta_export_prepare(). The
 * function will, however, not necessarily write as many bytes as returned by
 * kdbus_meta_export_prepare(); depending on the namespaces in question, it
 * might use up less than that.
 *
 * All information will be translated using the current namespaces.
 *
 * Return: 0 on success, negative error number otherwise.
 */
int kdbus_meta_export(struct kdbus_meta_proc *mp,
		      struct kdbus_meta_conn *mc,
		      u64 mask,
		      struct kdbus_pool_slice *slice,
		      off_t offset,
		      size_t *real_size)
{
	struct user_namespace *user_ns = current_user_ns();
	struct kdbus_item_header item_hdr[13], *hdr;
	char *exe_pathname = NULL;
	struct kdbus_creds creds;
	struct kdbus_pids pids;
	void *exe_page = NULL;
	struct kvec kvec[40];
	u64 *auxgrps = NULL;
	size_t cnt = 0;
	u64 size = 0;
	int ret = 0;

	hdr = &item_hdr[0];

	/*
	 * TODO: We currently have no sane way of translating a set of caps
	 * between different user namespaces. Until that changes, we have
	 * to drop such items.
	 */
	if (mp && mp->caps_namespace != user_ns)
		mask &= ~KDBUS_ATTACH_CAPS;

	if (mask == 0) {
		*real_size = 0;
		return 0;
	}

	/* process metadata */

	if (mp && (mask & KDBUS_ATTACH_CREDS)) {
		creds.uid	= kdbus_from_kuid_keep(mp->uid);
		creds.euid	= kdbus_from_kuid_keep(mp->euid);
		creds.suid	= kdbus_from_kuid_keep(mp->suid);
		creds.fsuid	= kdbus_from_kuid_keep(mp->fsuid);
		creds.gid	= kdbus_from_kgid_keep(mp->gid);
		creds.egid	= kdbus_from_kgid_keep(mp->egid);
		creds.sgid	= kdbus_from_kgid_keep(mp->sgid);
		creds.fsgid	= kdbus_from_kgid_keep(mp->fsgid);

		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++, KDBUS_ITEM_CREDS,
					    &creds, sizeof(creds), &size);
	}

	if (mp && (mask & KDBUS_ATTACH_PIDS)) {
		pids.pid = pid_vnr(mp->tgid);
		pids.tid = pid_vnr(mp->pid);
		pids.ppid = pid_vnr(mp->ppid);

		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++, KDBUS_ITEM_PIDS,
					    &pids, sizeof(pids), &size);
	}

	if (mp && (mask & KDBUS_ATTACH_AUXGROUPS)) {
		size_t payload_size = mp->n_auxgrps * sizeof(u64);
		int i;

		auxgrps = kmalloc(payload_size, GFP_KERNEL);
		if (!auxgrps) {
			ret = -ENOMEM;
			goto exit;
		}

		for (i = 0; i < mp->n_auxgrps; i++)
			auxgrps[i] = from_kgid_munged(user_ns, mp->auxgrps[i]);

		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_AUXGROUPS,
					    auxgrps, payload_size, &size);
	}

	if (mp && (mask & KDBUS_ATTACH_TID_COMM))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_TID_COMM, mp->tid_comm,
					    strlen(mp->tid_comm) + 1, &size);

	if (mp && (mask & KDBUS_ATTACH_PID_COMM))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_PID_COMM, mp->pid_comm,
					    strlen(mp->pid_comm) + 1, &size);

	if (mp && (mask & KDBUS_ATTACH_EXE)) {
		struct path p;

		/*
		 * TODO: We need access to __d_path() so we can write the path
		 * relative to conn->root_path. Once upstream, we need
		 * EXPORT_SYMBOL(__d_path) or an equivalent of d_path() that
		 * takes the root path directly. Until then, we drop this item
		 * if the root-paths differ.
		 */

		get_fs_root(current->fs, &p);
		if (path_equal(&p, &mp->root_path)) {
			exe_page = (void *)__get_free_page(GFP_TEMPORARY);
			if (!exe_page) {
				path_put(&p);
				ret = -ENOMEM;
				goto exit;
			}

			exe_pathname = d_path(&mp->exe_path, exe_page,
					      PAGE_SIZE);
			if (IS_ERR(exe_pathname)) {
				path_put(&p);
				ret = PTR_ERR(exe_pathname);
				goto exit;
			}

			cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
						    KDBUS_ITEM_EXE,
						    exe_pathname,
						    strlen(exe_pathname) + 1,
						    &size);
		}
		path_put(&p);
	}

	if (mp && (mask & KDBUS_ATTACH_CMDLINE))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_CMDLINE, mp->cmdline,
					    strlen(mp->cmdline) + 1, &size);

	if (mp && (mask & KDBUS_ATTACH_CGROUP))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_CGROUP, mp->cgroup,
					    strlen(mp->cgroup) + 1, &size);

	if (mp && (mask & KDBUS_ATTACH_CAPS))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_CAPS, &mp->caps,
					    sizeof(mp->caps), &size);

	if (mp && (mask & KDBUS_ATTACH_SECLABEL))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_SECLABEL, mp->seclabel,
					    strlen(mp->seclabel) + 1, &size);

	if (mp && (mask & KDBUS_ATTACH_AUDIT)) {
		struct kdbus_audit a = {
			.loginuid = from_kuid(user_ns, mp->audit_loginuid),
			.sessionid = mp->audit_sessionid,
		};

		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++, KDBUS_ITEM_AUDIT,
					    &a, sizeof(a), &size);
	}

	/* connection metadata */

	if (mc && (mask & KDBUS_ATTACH_NAMES))
		kdbus_kvec_set(&kvec[cnt++], mc->owned_names_items,
			       mc->owned_names_size, &size);

	if (mc && (mask & KDBUS_ATTACH_CONN_DESCRIPTION))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_CONN_DESCRIPTION,
					    mc->conn_description,
					    strlen(mc->conn_description) + 1,
					    &size);

	if (mc && (mask & KDBUS_ATTACH_TIMESTAMP))
		cnt += kdbus_meta_push_kvec(kvec + cnt, hdr++,
					    KDBUS_ITEM_TIMESTAMP, &mc->ts,
					    sizeof(mc->ts), &size);

	ret = kdbus_pool_slice_copy_kvec(slice, offset, kvec, cnt, size);
	*real_size = size;

exit:
	kfree(auxgrps);

	if (exe_page)
		free_page((unsigned long)exe_page);

	return ret;
}

/**
 * kdbus_meta_calc_attach_flags() - calculate attach flags for a sender
 *				    and a receiver
 * @sender:		Sending connection
 * @receiver:		Receiving connection
 *
 * Return: the attach flags both the sender and the receiver have opted-in
 * for.
 */
u64 kdbus_meta_calc_attach_flags(const struct kdbus_conn *sender,
				 const struct kdbus_conn *receiver)
{
	return atomic64_read(&sender->attach_flags_send) &
	       atomic64_read(&receiver->attach_flags_recv);
}
