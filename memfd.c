/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/aio.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/anon_inodes.h>

#include "memfd.h"

static const struct file_operations kdbus_memfd_fops;

struct kdbus_memfile {
	bool sealed;
	struct mutex lock;
	struct file *fp;
};

bool is_kdbus_memfd(const struct file *fp)
{
	return fp->f_op == &kdbus_memfd_fops;
}

bool is_kdbus_memfd_sealed(const struct file *fp)
{
	struct kdbus_memfile *mf = fp->private_data;
	bool sealed;

	mutex_lock(&mf->lock);
	sealed = mf->sealed;
	mutex_unlock(&mf->lock);

	return sealed;
}

u64 kdbus_memfd_size(const struct file *fp)
{
	struct kdbus_memfile *mf = fp->private_data;
	u64 size;

	mutex_lock(&mf->lock);
	size = i_size_read(file_inode(mf->fp));
	mutex_unlock(&mf->lock);

	return size;
}

/* create file and install a new file descriptor */
int kdbus_memfd_new(int *fd)
{
	struct kdbus_memfile *mf;
	struct file *shmemfp;
	struct file *fp;
	int f;
	int ret;

	mf = kzalloc(sizeof(struct kdbus_memfile), GFP_KERNEL);
	if (!mf)
		return -ENOMEM;

	mutex_init(&mf->lock);

	/* allocate a new unlinked shmem file */
	shmemfp = shmem_file_setup("kdbus", 0, 0);
	if (IS_ERR(shmemfp)) {
		ret = PTR_ERR(shmemfp);
		goto exit;
	}
	mf->fp = shmemfp;

	f = get_unused_fd_flags(O_CLOEXEC);
	if (f < 0) {
		ret = f;
		goto exit_shmem;
	}

	/* The anonymous exported inode ops cannot reach the otherwise
	 * invisible shmem inode. We rely on the fact that nothing else
	 * can create a new file for the shmem inode, like by opening the
	 * fd in /proc/$PID/fd/ */
	fp = anon_inode_getfile("[kdbus]", &kdbus_memfd_fops, mf, O_RDWR);
	if (IS_ERR(fp)) {
		ret = PTR_ERR(fp);
		goto exit_fd;
	}

	fp->f_mode |= FMODE_LSEEK;
	fp->f_mapping = shmemfp->f_mapping;
	fd_install(f, fp);

	*fd = f;
	return 0;

exit_fd:
	put_unused_fd(f);
exit_shmem:
	fput(shmemfp);
exit:
	kfree(mf);
	return ret;
}

static int kdbus_memfd_release(struct inode *ignored, struct file *file)
{
	struct kdbus_memfile *mf = file->private_data;

	fput(mf->fp);
	kfree(mf);
	return 0;
}

static loff_t kdbus_memfd_llseek(struct file *file, loff_t offset, int whence)
{
	struct kdbus_memfile *mf = file->private_data;
	loff_t ret;

	mutex_lock(&mf->lock);
	ret = mf->fp->f_op->llseek(mf->fp, offset, whence);
	if (ret < 0)
		goto exit;

	/* update the anonymous file */
	file->f_pos = mf->fp->f_pos;

exit:
	mutex_unlock(&mf->lock);
	return ret;
}

static ssize_t kdbus_memfd_readv(struct kiocb *iocb, const struct iovec *iov,
				 unsigned long iov_count, loff_t pos)
{
	struct kdbus_memfile *mf = iocb->ki_filp->private_data;
	ssize_t ret;

	mutex_lock(&mf->lock);
	iocb->ki_filp = mf->fp;
	ret = mf->fp->f_op->aio_read(iocb, iov, iov_count, pos);
	if (ret < 0)
		goto exit;

	/* update the shmem file */
	mf->fp->f_pos = iocb->ki_pos;

exit:
	mutex_unlock(&mf->lock);
	return ret;
}

static ssize_t kdbus_memfd_writev(struct kiocb *iocb, const struct iovec *iov,
				  unsigned long iov_count, loff_t pos)
{
	struct kdbus_memfile *mf = iocb->ki_filp->private_data;
	ssize_t ret;

	mutex_lock(&mf->lock);

	/* deny write access to a sealed file */
	if (mf->sealed) {
		ret = -EPERM;
		goto exit;
	}

	iocb->ki_filp = mf->fp;
	ret = mf->fp->f_op->aio_write(iocb, iov, iov_count, pos);
	if (ret < 0)
		goto exit;

	/* update the shmem file */
	mf->fp->f_pos = iocb->ki_pos;

exit:
	mutex_unlock(&mf->lock);
	return ret;
}

static int kdbus_memfd_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kdbus_memfile *mf = file->private_data;
	int ret = 0;

	mutex_lock(&mf->lock);

	if (vma->vm_flags & VM_WRITE) {
		size_t size;

		/* deny a writable mapping to a sealed file */
		if (mf->sealed) {
			ret = -EPERM;
			goto exit;
		}

		/* extend the size of the shmem file to the size of the mapping */
		size = (vma->vm_end - vma->vm_start) +
		       (vma->vm_pgoff << PAGE_SHIFT);
		if (size > i_size_read(file_inode(mf->fp))) {
			ret = vfs_truncate(&mf->fp->f_path, size);
			if (ret < 0)
				return ret;
		}
	}

	/* replace the anoymous inode file with our shmem file */
	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = get_file(mf->fp);
	ret = mf->fp->f_op->mmap(file, vma);

exit:
	mutex_unlock(&mf->lock);
	return ret;
}

static long
kdbus_memfd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct kdbus_memfile *mf = file->private_data;
	long ret = 0;

	mutex_lock(&mf->lock);
	switch (cmd) {
		case KDBUS_CMD_MEMFD_SIZE_GET: {
			u64 size = i_size_read(file_inode(mf->fp));
			u64 __user *addr = argp;

			if (put_user(size, addr)) {
				ret = -EFAULT;
				goto exit;
			}
			break;
		}

		case KDBUS_CMD_MEMFD_SIZE_SET: {
			int __user *addr = argp;
			u64 size;

			if (get_user(size, addr)) {
				ret = -EFAULT;
				goto exit;
			}

			/* deny a writable access to a sealed file */
			if (mf->sealed) {
				if (size == i_size_read(file_inode(mf->fp)))
					ret = -EALREADY;
				else
					ret = -EPERM;
				goto exit;
			}

			if (size != i_size_read(file_inode(mf->fp)))
				ret = vfs_truncate(&mf->fp->f_path, size);
			break;
		}

		case KDBUS_CMD_MEMFD_SEAL_GET: {
			int __user *addr = argp;

			if (put_user(mf->sealed, addr)) {
				ret = -EFAULT;
				goto exit;
			}
			break;
		}

		case KDBUS_CMD_MEMFD_SEAL_SET: {
			/*
			 * Make sure we have only one single user of the file
			 * before we seal, we rely on the fact there is no
			 * any other possibly writable references to the file.
			 */
			if (file_count(mf->fp) != 1) {
				if (mf->sealed == !!argp)
					ret = -EALREADY;
				else
					ret = -ETXTBSY;
				goto exit;
			}

			mf->sealed = !!argp;
			break;
		}

		default:
			ret = -ENOTTY;
			break;
	}

exit:
	mutex_unlock(&mf->lock);
	return ret;
}

static const struct file_operations kdbus_memfd_fops = {
	.owner =		THIS_MODULE,
	.release =		kdbus_memfd_release,
	.aio_read =		kdbus_memfd_readv,
	.aio_write =		kdbus_memfd_writev,
	.llseek =		kdbus_memfd_llseek,
	.mmap =			kdbus_memfd_mmap,
	.unlocked_ioctl =	kdbus_memfd_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =		kdbus_memfd_ioctl,
#endif
};
