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

#include <linux/aio.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "pool.h"
#include "util.h"

/**
 * struct kdbus_pool - the receiver's buffer
 * @f:			The backing shmem file
 * @size:		The size of the file
 * @busy:		The currently used size
 * @lock:		Pool data lock
 * @slices:		All slices sorted by address
 * @slices_busy:	Tree of allocated slices
 * @slices_free:	Tree of free slices
 *
 * The receiver's buffer, managed as a pool of allocated and free
 * slices containing the queued messages.
 *
 * Messages sent with KDBUS_CMD_SEND are copied direcly by the
 * sending process into the receiver's pool.
 *
 * Messages received with KDBUS_CMD_RECV just return the offset
 * to the data placed in the pool.
 *
 * The internally allocated memory needs to be returned by the receiver
 * with KDBUS_CMD_FREE.
 */
struct kdbus_pool {
	struct file *f;
	size_t size;
	size_t busy;
	struct mutex lock;

	struct list_head slices;
	struct rb_root slices_busy;
	struct rb_root slices_free;
};

/**
 * struct kdbus_pool_slice - allocated element in kdbus_pool
 * @pool:		Pool this slice belongs to
 * @off:		Offset of slice in the shmem file
 * @size:		Size of slice
 * @entry:		Entry in "all slices" list
 * @rb_node:		Entry in free or busy list
 * @child:		Child slice
 * @free:		Unused slice
 * @ref_kernel:		Kernel holds a reference
 * @ref_user:		Userspace holds a reference
 *
 * The pool has one or more slices, always spanning the entire size of the
 * pool.
 *
 * Every slice is an element in a list sorted by the buffer address, to
 * provide access to the next neighbor slice.
 *
 * Every slice is member in either the busy or the free tree. The free
 * tree is organized by slice size, the busy tree organized by buffer
 * offset.
 */
struct kdbus_pool_slice {
	struct kdbus_pool *pool;
	size_t off;
	size_t size;

	struct list_head entry;
	struct rb_node rb_node;
	struct kdbus_pool_slice *child;

	bool free:1;
	bool ref_kernel:1;
	bool ref_user:1;
};

static struct kdbus_pool_slice *kdbus_pool_slice_new(struct kdbus_pool *pool,
						     size_t off, size_t size)
{
	struct kdbus_pool_slice *slice;

	slice = kzalloc(sizeof(*slice), GFP_KERNEL);
	if (!slice)
		return NULL;

	slice->pool = pool;
	slice->off = off;
	slice->size = size;
	slice->free = true;
	return slice;
}

/* insert a slice into the free tree */
static void kdbus_pool_add_free_slice(struct kdbus_pool *pool,
				      struct kdbus_pool_slice *slice)
{
	struct rb_node **n;
	struct rb_node *pn = NULL;

	n = &pool->slices_free.rb_node;
	while (*n) {
		struct kdbus_pool_slice *pslice;

		pn = *n;
		pslice = rb_entry(pn, struct kdbus_pool_slice, rb_node);
		if (slice->size < pslice->size)
			n = &pn->rb_left;
		else
			n = &pn->rb_right;
	}

	rb_link_node(&slice->rb_node, pn, n);
	rb_insert_color(&slice->rb_node, &pool->slices_free);
}

/* insert a slice into the busy tree */
static void kdbus_pool_add_busy_slice(struct kdbus_pool *pool,
				      struct kdbus_pool_slice *slice)
{
	struct rb_node **n;
	struct rb_node *pn = NULL;

	n = &pool->slices_busy.rb_node;
	while (*n) {
		struct kdbus_pool_slice *pslice;

		pn = *n;
		pslice = rb_entry(pn, struct kdbus_pool_slice, rb_node);
		if (slice->off < pslice->off)
			n = &pn->rb_left;
		else if (slice->off > pslice->off)
			n = &pn->rb_right;
		else
			BUG();
	}

	rb_link_node(&slice->rb_node, pn, n);
	rb_insert_color(&slice->rb_node, &pool->slices_busy);
}

static struct kdbus_pool_slice *kdbus_pool_find_slice(struct kdbus_pool *pool,
						      size_t off)
{
	struct rb_node *n;

	n = pool->slices_busy.rb_node;
	while (n) {
		struct kdbus_pool_slice *s;

		s = rb_entry(n, struct kdbus_pool_slice, rb_node);
		if (off < s->off)
			n = n->rb_left;
		else if (off > s->off)
			n = n->rb_right;
		else
			return s;
	}

	return NULL;
}

/**
 * kdbus_pool_slice_alloc() - allocate memory from a pool
 * @pool:	The receiver's pool
 * @size:	The number of bytes to allocate
 * @kvec:	kvec to copy into the new slice, may be %NULL
 * @iovec:	iovec to copy into the new slice, may be %NULL
 * @vec_count:	Number of elements in @kvec or @iovec
 *
 * The returned slice is used for kdbus_pool_slice_release() to
 * free the allocated memory. If either @kvec or @iovec is non-NULL, the data
 * will be copied from kernel or userspace memory into the new slice at
 * offset 0.
 *
 * Return: the allocated slice on success, ERR_PTR on failure.
 */
struct kdbus_pool_slice *kdbus_pool_slice_alloc(struct kdbus_pool *pool,
						size_t size,
						struct kvec *kvec,
						struct iovec *iovec,
						size_t vec_count)
{
	size_t slice_size = KDBUS_ALIGN8(size);
	struct rb_node *n, *found = NULL;
	struct kdbus_pool_slice *s;
	int ret = 0;

	BUG_ON(kvec && iovec);

	/* search a free slice with the closest matching size */
	mutex_lock(&pool->lock);
	n = pool->slices_free.rb_node;
	while (n) {
		s = rb_entry(n, struct kdbus_pool_slice, rb_node);
		if (slice_size < s->size) {
			found = n;
			n = n->rb_left;
		} else if (slice_size > s->size) {
			n = n->rb_right;
		} else {
			found = n;
			break;
		}
	}

	/* no slice with the minimum size found in the pool */
	if (!found) {
		ret = -ENOBUFS;
		goto exit_unlock;
	}

	/* no exact match, use the closest one */
	if (!n) {
		struct kdbus_pool_slice *s_new;

		s = rb_entry(found, struct kdbus_pool_slice, rb_node);

		/* split-off the remainder of the size to its own slice */
		s_new = kdbus_pool_slice_new(pool, s->off + slice_size,
					     s->size - slice_size);
		if (!s_new) {
			ret = -ENOMEM;
			goto exit_unlock;
		}

		list_add(&s_new->entry, &s->entry);
		kdbus_pool_add_free_slice(pool, s_new);

		/* adjust our size now that we split-off another slice */
		s->size = slice_size;
	}

	/* move slice from free to the busy tree */
	rb_erase(found, &pool->slices_free);
	kdbus_pool_add_busy_slice(pool, s);

	WARN_ON(s->ref_kernel || s->ref_user);
	WARN_ON(s->child);

	s->ref_kernel = true;
	s->free = false;
	pool->busy += s->size;
	mutex_unlock(&pool->lock);

	if (kvec)
		ret = kdbus_pool_slice_copy_kvec(s, 0, kvec, vec_count, size);

	if (iovec)
		ret = kdbus_pool_slice_copy_iovec(s, 0, iovec, vec_count, size);

	if (ret < 0) {
		kdbus_pool_slice_release(s);
		return ERR_PTR(ret);
	}

	return s;

exit_unlock:
	mutex_unlock(&pool->lock);
	return ERR_PTR(ret);
}

static void __kdbus_pool_slice_release(struct kdbus_pool_slice *slice)
{
	struct kdbus_pool *pool = slice->pool;
	struct kdbus_pool_slice *child = slice->child;

	/* don't free the slice if either has a reference */
	if (slice->ref_kernel || slice->ref_user)
		return;

	BUG_ON(slice->free);

	rb_erase(&slice->rb_node, &pool->slices_busy);
	pool->busy -= slice->size;

	/* merge with the next free slice */
	if (!list_is_last(&slice->entry, &pool->slices)) {
		struct kdbus_pool_slice *s;

		s = list_entry(slice->entry.next,
			       struct kdbus_pool_slice, entry);
		if (s->free) {
			rb_erase(&s->rb_node, &pool->slices_free);
			list_del(&s->entry);
			slice->size += s->size;
			kfree(s);
		}
	}

	/* merge with previous free slice */
	if (pool->slices.next != &slice->entry) {
		struct kdbus_pool_slice *s;

		s = list_entry(slice->entry.prev,
			       struct kdbus_pool_slice, entry);
		if (s->free) {
			rb_erase(&s->rb_node, &pool->slices_free);
			list_del(&slice->entry);
			s->size += slice->size;
			kfree(slice);
			slice = s;
		}
	}

	slice->free = true;
	slice->child = NULL;
	kdbus_pool_add_free_slice(pool, slice);

	if (child) {
		/* Only allow one level of recursion */
		WARN_ON(child->child);
		WARN_ON(!child->ref_kernel);
		child->ref_kernel = false;
		__kdbus_pool_slice_release(child);
	}
}

/**
 * kdbus_pool_slice_release() - drop kernel-reference on allocated slice
 * @slice:		Slice allocated from the the pool
 *
 * This releases the kernel-reference on the given slice. If the
 * kernel-reference and the user-reference on a slice are dropped, the slice is
 * returned to the pool.
 *
 * So far, we do not implement full ref-counting on slices. Each, kernel and
 * user-space can have exactly one reference to a slice. If both are dropped at
 * the same time, the slice is released.
 */
void kdbus_pool_slice_release(struct kdbus_pool_slice *slice)
{
	struct kdbus_pool *pool;

	if (!slice)
		return;

	/* @slice may be freed, so keep local ptr to @pool */
	pool = slice->pool;

	mutex_lock(&pool->lock);
	/* kernel must own a ref to @slice to drop it */
	WARN_ON(!slice->ref_kernel);
	slice->ref_kernel = false;
	__kdbus_pool_slice_release(slice);
	mutex_unlock(&pool->lock);
}

/**
 * kdbus_pool_release_offset() - release a public offset
 * @pool:		pool to operate on
 * @off:		offset to release
 *
 * This should be called whenever user-space frees a slice given to them. It
 * verifies the slice is available and public, and then drops it. It ensures
 * correct locking and barriers against queues.
 *
 * Return: 0 on success, ENXIO if the offset is invalid or not public.
 */
int kdbus_pool_release_offset(struct kdbus_pool *pool, size_t off)
{
	struct kdbus_pool_slice *slice;
	int ret = 0;

	mutex_lock(&pool->lock);
	slice = kdbus_pool_find_slice(pool, off);
	if (slice && slice->ref_user) {
		slice->ref_user = false;
		__kdbus_pool_slice_release(slice);
	} else {
		ret = -ENXIO;
	}
	mutex_unlock(&pool->lock);

	return ret;
}

/**
 * kdbus_pool_slice_publish() - publish slice to user-space
 * @slice:		The slice
 * @out_offset:		Output storage for offset, or NULL
 * @out_size:		Output storage for size, or NULL
 *
 * This prepares a slice to be published to user-space.
 *
 * This call combines the following operations:
 *   * the memory region is flushed so the user's memory view is consistent
 *   * the slice is marked as referenced by user-space, so user-space has to
 *     call KDBUS_CMD_FREE to release it
 *   * the offset and size of the slice are written to the given output
 *     arguments, if non-NULL
 */
void kdbus_pool_slice_publish(struct kdbus_pool_slice *slice,
			      u64 *out_offset, u64 *out_size)
{
	mutex_lock(&slice->pool->lock);
	/* kernel must own a ref to @slice to gain a user-space ref */
	WARN_ON(!slice->ref_kernel);
	slice->ref_user = true;
	mutex_unlock(&slice->pool->lock);

	if (out_offset)
		*out_offset = slice->off;
	if (out_size)
		*out_size = slice->size;
}

/**
 * kdbus_pool_slice_offset() - Get a slice's offset inside the pool
 * @slice:	Slice to return the offset of
 *
 * Return: The internal offset @slice inside the pool.
 */
off_t kdbus_pool_slice_offset(const struct kdbus_pool_slice *slice)
{
	return slice->off;
}

/**
 * kdbus_pool_slice_set_child() - Set child of a slice
 * @slice:	Slice to add a child to
 * @child:	Child to set, may be %NULL
 *
 * Set @child as child of @slice, so it will be freed automatically when
 * @slice goes away.
 */
void kdbus_pool_slice_set_child(struct kdbus_pool_slice *slice,
				struct kdbus_pool_slice *child)
{
	BUG_ON(child && slice->pool != child->pool);
	WARN_ON(slice->child);
	slice->child = child;
}

/**
 * kdbus_pool_new() - create a new pool
 * @name:		Name of the (deleted) file which shows up in
 *			/proc, used for debugging
 * @size:		Maximum size of the pool
 *
 * Return: a new kdbus_pool on success, ERR_PTR on failure.
 */
struct kdbus_pool *kdbus_pool_new(const char *name, size_t size)
{
	struct kdbus_pool_slice *s;
	struct kdbus_pool *p;
	struct file *f;
	char *n = NULL;
	int ret;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	if (name) {
		n = kasprintf(GFP_KERNEL, KBUILD_MODNAME "-conn:%s", name);
		if (!n) {
			ret = -ENOMEM;
			goto exit_free;
		}
	}

	f = shmem_file_setup(n ?: KBUILD_MODNAME "-conn", size, VM_NORESERVE);
	kfree(n);

	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto exit_free;
	}

	ret = get_write_access(file_inode(f));
	if (ret < 0)
		goto exit_put_shmem;

	/* allocate first slice spanning the entire pool */
	s = kdbus_pool_slice_new(p, 0, size);
	if (!s) {
		ret = -ENOMEM;
		goto exit_put_write;
	}

	p->f = f;
	p->size = size;
	p->busy = 0;
	p->slices_free = RB_ROOT;
	p->slices_busy = RB_ROOT;
	mutex_init(&p->lock);

	INIT_LIST_HEAD(&p->slices);
	list_add(&s->entry, &p->slices);

	kdbus_pool_add_free_slice(p, s);
	return p;

exit_put_write:
	put_write_access(file_inode(f));
exit_put_shmem:
	fput(f);
exit_free:
	kfree(p);
	return ERR_PTR(ret);
}

/**
 * kdbus_pool_free() - destroy pool
 * @pool:		The receiver's pool
 */
void kdbus_pool_free(struct kdbus_pool *pool)
{
	struct kdbus_pool_slice *s, *tmp;

	if (!pool)
		return;

	list_for_each_entry_safe(s, tmp, &pool->slices, entry) {
		list_del(&s->entry);
		kfree(s);
	}

	put_write_access(file_inode(pool->f));
	fput(pool->f);
	kfree(pool);
}

/**
 * kdbus_pool_remain() - the number of free bytes in the pool
 * @pool:		The receiver's pool
 *
 * Return: the number of unallocated bytes in the pool
 */
size_t kdbus_pool_remain(struct kdbus_pool *pool)
{
	size_t size;

	mutex_lock(&pool->lock);
	size = pool->size - pool->busy;
	mutex_unlock(&pool->lock);

	return size;
}

/**
 * kdbus_pool_slice_copy_iovec() - copy user memory to a slice
 * @slice:		The slice to write to
 * @off:		Offset in the slice to write to
 * @iov:		iovec array, pointing to data to copy
 * @iov_len:		Number of elements in @iov
 * @total_len:		Total number of bytes described in members of @iov
 *
 * User memory referenced by @iov will be copied into @slice at offset @off.
 *
 * Return: the numbers of bytes copied, negative errno on failure.
 */
ssize_t
kdbus_pool_slice_copy_iovec(const struct kdbus_pool_slice *slice, size_t off,
			    struct iovec *iov, size_t iov_len, size_t total_len)
{
	struct file *f = slice->pool->f;
	struct iov_iter iter;
	struct kiocb kiocb;
	ssize_t len;

	BUG_ON(off + total_len > slice->size);

	init_sync_kiocb(&kiocb, f);
	kiocb.ki_pos = slice->off + off;
	kiocb.ki_nbytes = total_len;
	iov_iter_init(&iter, WRITE, iov, iov_len, total_len);

	len = f->f_op->write_iter(&kiocb, &iter);
	if (len < 0)
		return len;

	if (len != total_len)
		return -EFAULT;

	return len;
}

/**
 * kdbus_pool_slice_copy_kvec() - copy kernel memory to a slice
 * @slice:		The slice to write to
 * @off:		Offset in the slice to write to
 * @kvec:		kvec array, pointing to data to copy
 * @kvec_len:		Number of elements in @kvec
 * @total_len:		Total number of bytes described in members of @kvec
 *
 * Kernel memory referenced by @kvec will be copied into @slice at offset @off.
 *
 * Return: the numbers of bytes copied, negative errno on failure.
 */
ssize_t kdbus_pool_slice_copy_kvec(const struct kdbus_pool_slice *slice,
				   size_t off, struct kvec *kvec,
				   size_t kvec_len, size_t total_len)
{
	struct file *f = slice->pool->f;
	struct iov_iter iter;
	mm_segment_t old_fs;
	struct kiocb kiocb;
	ssize_t len;

	BUG_ON(off + total_len > slice->size);

	old_fs = get_fs();
	set_fs(get_ds());

	init_sync_kiocb(&kiocb, f);
	kiocb.ki_pos = slice->off + off;
	kiocb.ki_nbytes = total_len;

	/* FIXME: replace with iov_iter_kvec() once 3.19-rc1 is out */
	iov_iter_init(&iter, WRITE | ITER_KVEC, (struct iovec *)kvec,
		      kvec_len, total_len);

	len = f->f_op->write_iter(&kiocb, &iter);
	set_fs(old_fs);

	if (len < 0)
		return len;

	if (len != total_len)
		return -EFAULT;

	return len;
}

static int kdbus_pool_copy(const struct kdbus_pool_slice *slice_dst,
			   const struct kdbus_pool_slice *slice_src)
{
	struct file *f_src = slice_src->pool->f;
	struct file *f_dst = slice_dst->pool->f;
	struct inode *i_dst = file_inode(f_dst);
	struct address_space *mapping_dst = f_dst->f_mapping;
	const struct address_space_operations *aops = mapping_dst->a_ops;
	unsigned long len = slice_src->size;
	loff_t off_src = slice_src->off;
	loff_t off_dst = slice_dst->off;
	int ret = 0;

	BUG_ON(slice_src->size != slice_dst->size);
	BUG_ON(slice_src->free || slice_dst->free);

	mutex_lock(&i_dst->i_mutex);

	while (len > 0) {
		unsigned long page_off;
		unsigned long copy_len;
		char __user *kaddr;
		struct page *page;
		ssize_t n_read;
		void *fsdata;
		int status;

		page_off = off_dst & (PAGE_CACHE_SIZE - 1);
		copy_len = min_t(unsigned long,
				 PAGE_CACHE_SIZE - page_off, len);

		status = aops->write_begin(f_dst, mapping_dst, off_dst,
					   copy_len, 0, &page, &fsdata);
		if (status) {
			ret = -EFAULT;
			break;
		}

		kaddr = (char __force __user *)kmap(page) + page_off;
		n_read = f_src->f_op->read(f_src, kaddr, copy_len, &off_src);
		kunmap(page);
		mark_page_accessed(page);
		flush_dcache_page(page);

		status = aops->write_end(f_dst, mapping_dst, off_dst,
					 copy_len, copy_len, page, fsdata);

		if (n_read < 0) {
			ret = n_read;
			break;
		}

		if (n_read != status) {
			ret = -EFAULT;
			break;
		}

		off_dst += copy_len;
		len -= copy_len;
	}

	mutex_unlock(&i_dst->i_mutex);

	return ret;
}

/**
 * kdbus_pool_slice_move() - move memory from one pool into another one
 * @pool_dst:		The receiver's pool to copy to
 * @slice:		Reference to the slice to copy from the source;
 *			updated with the newly allocated slice in the
 *			destination
 *
 * Move memory from one pool to another. A slice will be allocated in the
 * destination pool, the original memory from the existing slice is copied
 * over, and the existing slice will be released.
 *
 * Return: 0 on success, negative error number on failure.
 */
int kdbus_pool_slice_move(struct kdbus_pool *pool_dst,
			  struct kdbus_pool_slice **slice)
{
	mm_segment_t old_fs;
	struct kdbus_pool_slice *slice_new;
	int ret;

	slice_new = kdbus_pool_slice_alloc(pool_dst, (*slice)->size,
					   NULL, NULL, 0);
	if (IS_ERR(slice_new))
		return PTR_ERR(slice_new);

	old_fs = get_fs();
	set_fs(get_ds());
	ret = kdbus_pool_copy(slice_new, *slice);
	set_fs(old_fs);
	if (ret < 0)
		goto exit_free;

	kdbus_pool_slice_release(*slice);

	*slice = slice_new;
	return 0;

exit_free:
	kdbus_pool_slice_release(slice_new);
	return ret;
}

/**
 * kdbus_pool_mmap() -  map the pool into the process
 * @pool:		The receiver's pool
 * @vma:		passed by mmap() syscall
 *
 * Return: the result of the mmap() call, negative errno on failure.
 */
int kdbus_pool_mmap(const struct kdbus_pool *pool, struct vm_area_struct *vma)
{
	/* deny write access to the pool */
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;
	vma->vm_flags &= ~VM_MAYWRITE;

	/* do not allow to map more than the size of the file */
	if ((vma->vm_end - vma->vm_start) > pool->size)
		return -EFAULT;

	/* replace the connection file with our shmem file */
	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = get_file(pool->f);

	return pool->f->f_op->mmap(pool->f, vma);
}
