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

struct kdbus_fs_super {
	struct kdbus_domain *domain;
};

#define kdbus_node_from_dentry(_dentry) \
	((struct kdbus_node*)(_dentry)->d_fsdata)
#define kdbus_node_from_inode(_inode) \
	((struct kdbus_node*)(_inode)->i_private)

static struct inode *fs_inode_get(struct super_block *sb,
				  struct kdbus_node *node);

/*
 * linux/magic.h
 */
#define KDBUS_SUPER_MAGIC 0x19910104

/*
 * File Management
 */

static int fs_file_fop_open(struct inode *inode, struct file *filp)
{
	const struct file_operations *fops = &kdbus_handle_ops;

	fops = fops_get(fops);
	if (!fops)
		return -ENXIO;

	replace_fops(filp, fops);
	if (!filp->f_op->open)
		return 0;

	filp->private_data = kdbus_node_find_by_id(inode->i_ino);

	return filp->f_op->open(inode, filp);
}

static const struct file_operations fs_file_fops = {
	.open		= fs_file_fop_open,
	.llseek		= noop_llseek,
};

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
	struct kdbus_node *old = file->private_data;
	struct kdbus_node *pos, *next;
	struct rb_node *rb;

	if (!dir_emit_dots(file, ctx))
		return 0;

	next = old;

	mutex_lock(&parent->lock);
	do {
		if (!next || ctx->pos != next->hash) {
			/* find first node with: hash >= ctx->pos */
			next = NULL;
			rb = parent->children.rb_node;
			while (rb) {
				pos = kdbus_node_from_rb(rb);

				if (ctx->pos < pos->hash) {
					rb = rb->rb_left;
					next = pos;
				} else if (ctx->pos > pos->hash) {
					rb = rb->rb_right;
				} else {
					next = pos;
					break;
				}
			}
		}

		while (next && !kdbus_node_is_active(next)) {
			rb = rb_next(&next->rb);
			if (rb)
				next = kdbus_node_from_rb(rb);
			else
				next = NULL;
		}

		if (!next)
			break;

		file->private_data = kdbus_node_ref(next);
		ctx->pos = next->hash;

		mutex_unlock(&parent->lock);

		/* unref old entry only if parent mutex is released */
		kdbus_node_unref(old);
		old = file->private_data;

		if (!dir_emit(ctx, next->name, strlen(next->name), next->id,
			      kdbus_dt_type(next)))
			return 0;

		mutex_lock(&parent->lock);

		rb = rb_next(&next->rb);
		if (rb) {
			next = kdbus_node_from_rb(rb);
			ctx->pos = next->hash;
		} else {
			next = NULL;
		}
	} while (next);
	mutex_unlock(&parent->lock);

	kdbus_node_unref(old);
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
	struct kdbus_node *parent;
	struct kdbus_node *node;
	struct inode *inode;
	struct rb_node *rb;
	unsigned int hash;
	const char *name;
	int ret;

	parent = kdbus_node_from_dentry(dentry->d_parent);
	name = dentry->d_name.name;
	hash = kdbus_node_name_hash(name);

	mutex_lock(&parent->lock);
	rb = parent->children.rb_node;
	while (rb) {
		node = kdbus_node_from_rb(rb);
		ret = kdbus_node_name_compare(hash, name, node);
		if (ret < 0)
			rb = rb->rb_left;
		else if (ret > 0)
			rb = rb->rb_right;
		else
			break;
	}
	if (rb && kdbus_node_is_active(node))
		kdbus_node_ref(node);
	else
		node = NULL;
	mutex_unlock(&parent->lock);

	if (!node)
		return NULL;

	dentry->d_fsdata = node;
	inode = fs_inode_get(dir->i_sb, node);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	return d_materialise_unique(dentry, inode);
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
	case KDBUS_NODE_ENDPOINT:
		inode->i_mode |= S_IFREG;
		inode->i_op = &fs_inode_iops;
		inode->i_fop = &fs_file_fops;
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

static struct kdbus_fs_super *fs_super_new(void)
{
	struct kdbus_fs_super *super;
	int ret;

	super = kzalloc(sizeof(*super), GFP_KERNEL);
	if (!super)
		return ERR_PTR(-ENOMEM);

	super->domain = kdbus_domain_new(NULL, KDBUS_MAKE_ACCESS_WORLD);
	if (IS_ERR(super->domain)) {
		ret = PTR_ERR(super->domain);
		goto exit_free;
	}

	ret = kdbus_domain_activate(super->domain);
	if (ret < 0)
		goto exit_domain;

	return super;

exit_domain:
	kdbus_domain_unref(super->domain);
exit_free:
	kfree(super);
	return ERR_PTR(ret);
}

static void fs_super_free(struct kdbus_fs_super *super)
{
	if (!super)
		return;

	kdbus_domain_deactivate(super->domain);
	kdbus_domain_unref(super->domain);
	kfree(super);
}

static int fs_super_fill(struct super_block *sb)
{
	struct kdbus_fs_super *super = sb->s_fs_info;
	struct inode *inode;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = KDBUS_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &fs_super_sops;
	sb->s_time_gran = 1;

	inode = fs_inode_get(sb, &super->domain->node);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	sb->s_root->d_fsdata = kdbus_node_ref(&super->domain->node);
	sb->s_d_op = &fs_super_dops;
	sb->s_flags |= MS_ACTIVE;

	return 0;
}

static void fs_super_kill(struct super_block *sb)
{
	struct kdbus_fs_super *super = sb->s_fs_info;
	struct kdbus_node *node = NULL;

	if (sb->s_root)
		node = sb->s_root->d_fsdata;
	kill_anon_super(sb);
	kdbus_node_unref(node);
	fs_super_free(super);
}

static int fs_super_compare(struct super_block *sb, void *data)
{
	return 0;
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
	struct kdbus_fs_super *super;
	struct super_block *sb;
	int ret;

	super = fs_super_new();
	if (IS_ERR(super))
		return ERR_CAST(super);

	sb = sget(fs_type, fs_super_compare, fs_super_set, flags, super);
	if (IS_ERR(sb) || sb->s_fs_info != super)
		fs_super_free(super);
	if (IS_ERR(sb))
		return ERR_CAST(sb);

	if (!sb->s_root) {
		ret = fs_super_fill(sb);
		if (ret < 0)
			goto exit_sput;
	}

	return dget(sb->s_root);

exit_sput:
	deactivate_locked_super(sb);
	return ERR_PTR(ret);
}

static struct file_system_type fs_type = {
	.name		= "kdbusfs",
	.owner		= THIS_MODULE,
	.mount		= fs_super_mount,
	.kill_sb	= fs_super_kill,
};

/**
 * kdbus_fs_exit() - unregister kdbus filesystem
 *
 * Return: 0 on success, negative error otherwise.
 */
int kdbus_fs_init(void)
{
	return register_filesystem(&fs_type);
}

/**
 * kdbus_fs_exit() - unregister kdbus filesystem
 */
void kdbus_fs_exit(void)
{
	unregister_filesystem(&fs_type);
}
