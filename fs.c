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

#include <linux/backing-dev.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/init.h>
#include <linux/ipc_namespace.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "bus.h"
#include "domain.h"
#include "endpoint.h"
#include "fs.h"
#include "handle.h"
#include "node.h"

#define kdbus_node_from_dentry(_dentry) \
	((struct kdbus_node *)(_dentry)->d_fsdata)
#define kdbus_node_from_inode(_inode) \
	((struct kdbus_node *)(_inode)->i_private)

static struct inode *fs_inode_get(struct super_block *sb,
				  struct kdbus_node *node);

/*
 * linux/magic.h
 */
#define KDBUS_SUPER_MAGIC 0x44427573

/*
 * Directory Management
 */

static inline unsigned char kdbus_dt_type(struct kdbus_node *node)
{
	switch (node->type) {
	case KDBUS_NODE_DOMAIN:
	case KDBUS_NODE_BUS:
		return DT_DIR;
	case KDBUS_NODE_CONTROL:
	case KDBUS_NODE_ENDPOINT:
		return DT_REG;
	}

	return DT_UNKNOWN;
}

static int fs_dir_fop_iterate(struct file *file, struct dir_context *ctx)
{
	struct dentry *dentry = file->f_path.dentry;
	struct kdbus_node *parent = kdbus_node_from_dentry(dentry);
	struct kdbus_node *old, *next = file->private_data;

	/*
	 * kdbusfs directory iterator (modelled after sysfs/kernfs)
	 * When iterating kdbusfs directories, we iterate all children of the
	 * parent kdbus_node object. We use ctx->pos to store the hash of the
	 * child and file->private_data to store a reference to the next node
	 * object. If ctx->pos is not modified via llseek while you iterate a
	 * directory, then we use the file->private_data node pointer to
	 * directly access the next node in the tree.
	 * However, if you directly seek on the directory, we have to find the
	 * closest node to that position and cannot use our node pointer. This
	 * means iterating the rb-tree to find the closest match and start over
	 * from there.
	 * Note that hash values are not neccessarily unique. Therefore, llseek
	 * is not guaranteed to seek to the same node that you got when you
	 * retrieved the position. Seeking to 0, 1, 2 and >=INT_MAX is safe,
	 * though. We could use the inode-number as position, but this would
	 * require another rb-tree for fast access. Kernfs and others already
	 * ignore those conflicts, so we should be fine, too.
	 */

	if (!dir_emit_dots(file, ctx))
		return 0;

	/* acquire @next; if deactivated, or seek detected, find next node */
	old = next;
	if (next && ctx->pos == next->hash) {
		if (kdbus_node_acquire(next))
			kdbus_node_ref(next);
		else
			next = kdbus_node_next_child(parent, next);
	} else {
		next = kdbus_node_find_closest(parent, ctx->pos);
	}
	kdbus_node_unref(old);

	while (next) {
		/* emit @next */
		file->private_data = next;
		ctx->pos = next->hash;

		kdbus_node_release(next);

		if (!dir_emit(ctx, next->name, strlen(next->name), next->id,
			      kdbus_dt_type(next)))
			return 0;

		/* find next node after @next */
		old = next;
		next = kdbus_node_next_child(parent, next);
		kdbus_node_unref(old);
	}

	file->private_data = NULL;
	ctx->pos = INT_MAX;

	return 0;
}

static loff_t fs_dir_fop_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t ret;

	/* protect f_off against fop_iterate */
	mutex_lock(&inode->i_mutex);
	ret = generic_file_llseek(file, offset, whence);
	mutex_unlock(&inode->i_mutex);

	return ret;
}

static int fs_dir_fop_release(struct inode *inode, struct file *file)
{
	kdbus_node_unref(file->private_data);
	return 0;
}

static const struct file_operations fs_dir_fops = {
	.read		= generic_read_dir,
	.iterate	= fs_dir_fop_iterate,
	.llseek		= fs_dir_fop_llseek,
	.release	= fs_dir_fop_release,
};

static struct dentry *fs_dir_iop_lookup(struct inode *dir,
					struct dentry *dentry,
					unsigned int flags)
{
	struct dentry *dnew = NULL;
	struct kdbus_node *parent;
	struct kdbus_node *node;
	struct inode *inode;

	parent = kdbus_node_from_dentry(dentry->d_parent);
	if (!kdbus_node_acquire(parent))
		return NULL;

	/* returns reference to _acquired_ child node */
	node = kdbus_node_find_child(parent, dentry->d_name.name);
	if (node) {
		dentry->d_fsdata = node;
		inode = fs_inode_get(dir->i_sb, node);
		if (IS_ERR(inode))
			dnew = ERR_CAST(inode);
		else
			dnew = d_materialise_unique(dentry, inode);

		kdbus_node_release(node);
	}

	kdbus_node_release(parent);
	return dnew;
}

static const struct inode_operations fs_dir_iops = {
	.permission	= generic_permission,
	.lookup		= fs_dir_iop_lookup,
};

/*
 * Inode Management
 */

static const struct inode_operations fs_inode_iops = {
	.permission	= generic_permission,
};

static struct inode *fs_inode_get(struct super_block *sb,
				  struct kdbus_node *node)
{
	struct inode *inode;

	inode = iget_locked(sb, node->id);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	inode->i_private = kdbus_node_ref(node);
	inode->i_mapping->a_ops = &empty_aops;
	inode->i_mapping->backing_dev_info = &noop_backing_dev_info;
	inode->i_mode = node->mode & S_IALLUGO;
	inode->i_atime = inode->i_ctime = inode->i_mtime = CURRENT_TIME;
	inode->i_uid = node->uid;
	inode->i_gid = node->gid;

	switch (node->type) {
	case KDBUS_NODE_DOMAIN:
	case KDBUS_NODE_BUS:
		inode->i_mode |= S_IFDIR;
		inode->i_op = &fs_dir_iops;
		inode->i_fop = &fs_dir_fops;
		set_nlink(inode, 2);
		break;
	case KDBUS_NODE_CONTROL:
		inode->i_mode |= S_IFREG;
		inode->i_op = &fs_inode_iops;
		inode->i_fop = &kdbus_handle_control_ops;
		break;
	case KDBUS_NODE_ENDPOINT:
		inode->i_mode |= S_IFREG;
		inode->i_op = &fs_inode_iops;
		inode->i_fop = &kdbus_handle_ep_ops;
		break;
	}

	unlock_new_inode(inode);

	return inode;
}

/*
 * Superblock Management
 */

static int fs_super_dop_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct kdbus_node *node;

	/* Force lookup on negatives */
	if (!dentry->d_inode)
		return 0;

	node = kdbus_node_from_dentry(dentry);

	/* see whether the node has been removed */
	if (!kdbus_node_is_active(node))
		return 0;

	return 1;
}

static void fs_super_dop_release(struct dentry *dentry)
{
	kdbus_node_unref(dentry->d_fsdata);
}

static const struct dentry_operations fs_super_dops = {
	.d_revalidate	= fs_super_dop_revalidate,
	.d_release	= fs_super_dop_release,
};

static void fs_super_sop_evict_inode(struct inode *inode)
{
	struct kdbus_node *node = kdbus_node_from_inode(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	kdbus_node_unref(node);
}

static const struct super_operations fs_super_sops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= fs_super_sop_evict_inode,
};

static int fs_super_fill(struct super_block *sb)
{
	struct kdbus_domain *domain = sb->s_fs_info;
	struct inode *inode;
	int ret;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = KDBUS_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &fs_super_sops;
	sb->s_time_gran = 1;

	inode = fs_inode_get(sb, &domain->node);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		/* d_make_root iput()s the inode on failure */
		return -ENOMEM;
	}

	/* sb holds domain reference */
	sb->s_root->d_fsdata = &domain->node;
	sb->s_d_op = &fs_super_dops;

	ret = kdbus_domain_activate(domain);
	if (ret < 0)
		return ret;

	sb->s_flags |= MS_ACTIVE;
	return 0;
}

static void fs_super_kill(struct super_block *sb)
{
	struct kdbus_domain *domain = sb->s_fs_info;

	if (domain) {
		kdbus_domain_deactivate(domain);
	}

	kill_anon_super(sb);

	if (domain)
		kdbus_domain_unref(domain);
}

static int fs_super_set(struct super_block *sb, void *data)
{
	int ret;

	ret = set_anon_super(sb, data);
	if (!ret)
		sb->s_fs_info = data;

	return ret;
}

static struct dentry *fs_super_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *data)
{
	struct kdbus_domain *domain;
	struct super_block *sb;
	int ret;

	domain = kdbus_domain_new(KDBUS_MAKE_ACCESS_WORLD);
	if (IS_ERR(domain))
		return ERR_CAST(domain);

	sb = sget(fs_type, NULL, fs_super_set, flags, domain);
	if (IS_ERR(sb)) {
		ret = PTR_ERR(sb);
		goto exit_domain;
	}

	WARN_ON(sb->s_fs_info != domain);
	WARN_ON(sb->s_root);

	ret = fs_super_fill(sb);
	if (ret < 0) {
		/* calls into ->kill_sb() when done */
		deactivate_locked_super(sb);
		return ERR_PTR(ret);
	}

	return dget(sb->s_root);

exit_domain:
	kdbus_domain_deactivate(domain);
	kdbus_domain_unref(domain);
	return ERR_PTR(ret);
}

static struct file_system_type fs_type = {
	.name		= KBUILD_MODNAME "fs",
	.owner		= THIS_MODULE,
	.mount		= fs_super_mount,
	.kill_sb	= fs_super_kill,
	.fs_flags	= FS_USERNS_MOUNT,
};

/**
 * kdbus_fs_init() - register kdbus filesystem
 *
 * This registers a filesystem with the VFS layer. The filesystem is called
 * `KBUILD_MODNAME "fs"', which usually resolves to `kdbusfs'. The nameing
 * scheme allows to set KBUILD_MODNAME to "kdbus2" and you will get an
 * independent filesystem for developers.
 *
 * Each mount of the kdbusfs filesystem has an kdbus_domain attached.
 * Operations on this mount will only affect the attached domain. On each mount
 * a new domain is automatically created and used for this mount exclusively.
 * If you want to share a domain across multiple mounts, you need to bind-mount
 * it.
 *
 * Mounts of kdbusfs (with a different domain each) are unrelated to each other
 * and will never have any effect on any domain but their own.
 *
 * Return: 0 on success, negative error otherwise.
 */
int kdbus_fs_init(void)
{
	return register_filesystem(&fs_type);
}

/**
 * kdbus_fs_exit() - unregister kdbus filesystem
 *
 * This does the reverse to kdbus_fs_init(). It unregisters the kdbusfs
 * filesystem from VFS and cleans up any allocated resources.
 */
void kdbus_fs_exit(void)
{
	unregister_filesystem(&fs_type);
}
