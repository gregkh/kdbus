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
 * Messages sent with KDBUS_CMD_MSG_SEND are copied direcly by the
 * sending process into the receiver's pool.
 *
 * Messages received with KDBUS_CMD_MSG_RECV just return the offset
 * to the data placed in the pool.
 *
 * The internally allocated memory needs to be returned by the receiver
 * with KDBUS_CMD_MSG_FREE.
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
 * @free:		Unused slice
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
	bool free;
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
	}

	rb_link_node(&slice->rb_node, pn, n);
	rb_insert_color(&slice->rb_node, &pool->slices_busy);
}

/**
 * kdbus_pool_slice_find() - find a slice by its offset
 * @pool:		The receiver's pool
 * @off:		The offset of the slice in the pool
 *
 * Return: allocated slice, NULL on failure.
 */
struct kdbus_pool_slice *kdbus_pool_slice_find(struct kdbus_pool *pool,
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
 * @pool:		The receiver's pool
 * @slice:		Slice allocated from the the pool
 * @size:		The number of bytes to allocate
 *
 * The returned slice is used for kdbus_pool_slice_free() to
 * free the allocated memory.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_pool_slice_alloc(struct kdbus_pool *pool,
			   struct kdbus_pool_slice **slice, size_t size)
{
	size_t slice_size = KDBUS_ALIGN8(size);
	struct rb_node *n, *found = NULL;
	struct kdbus_pool_slice *s;
	int ret = 0;

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
	if (!found)
		return -ENOBUFS;

	/* no exact match, use the closest one */
	if (!n)
		s = rb_entry(found, struct kdbus_pool_slice, rb_node);

	/* move slice from free to the busy tree */
	rb_erase(found, &pool->slices_free);
	kdbus_pool_add_busy_slice(pool, s);

	/* we got a slice larger than what we asked for? */
	if (s->size > slice_size) {
		struct kdbus_pool_slice *s_new;

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

	s->free = false;
	pool->busy += s->size;
	mutex_unlock(&pool->lock);

	*slice = s;
exit_unlock:
	return ret;
}

/**
 * kdbus_pool_slice_free() - give allocated memory back to the pool
 * @slice:		Slice allocated from the the pool
 *
 * The slice was returned by the call to kdbus_pool_alloc_slice(), the
 * memory is returned to the pool.
 */
void kdbus_pool_slice_free(struct kdbus_pool_slice *slice)
{
	struct kdbus_pool *pool = slice->pool;

	mutex_lock(&slice->pool->lock);
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

		s = list_entry(slice->entry.prev, struct kdbus_pool_slice,
			       entry);
		if (s->free) {
			rb_erase(&s->rb_node, &pool->slices_free);
			list_del(&slice->entry);
			s->size += slice->size;
			kfree(slice);
			slice = s;
		}
	}

	slice->free = true;
	kdbus_pool_add_free_slice(pool, slice);
	mutex_unlock(&slice->pool->lock);
}

/**
 * kdbus_pool_slice_offset() - return the slice offset in the pool
 * @slice:		The Slice
 *
 * Return: the offset in bytes.
 */
size_t kdbus_pool_slice_offset(const struct kdbus_pool_slice *slice)
{
	return slice->off;
}

/**
 * kdbus_pool_new() - create a new pool
 * @name:		Name of the (deleted) file which shows up in
 *			/proc, used for debugging
 * @pool:		Newly allocated pool
 * @size:		Maximum size of the pool
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_pool_new(const char *name, struct kdbus_pool **pool, size_t size)
{
	struct kdbus_pool_slice *s;
	struct kdbus_pool *p;
	struct file *f;
	int ret;

	BUG_ON(*pool);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	if (name) {
		char *n;

		n = kasprintf(GFP_KERNEL, KBUILD_MODNAME "-conn:%s", name);
		if (!n) {
			ret = -ENOMEM;
			goto exit_free;
		}
		f = shmem_file_setup(n, size, 0);
		kfree(n);
	} else {
		f = shmem_file_setup(KBUILD_MODNAME "-conn", size, 0);
	}
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto exit_free;
	}

	/* allocate first slice spanning the entire pool */
	s = kdbus_pool_slice_new(p, 0, size);
	if (!s) {
		ret = -ENOMEM;
		goto exit_put_shmem;
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
	*pool = p;
	return 0;

exit_put_shmem:
	fput(f);
exit_free:
	kfree(p);
	return ret;
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

/* copy data from a file to a page in the receiver's pool */
static int kdbus_pool_copy_file(struct page *p, size_t start,
				struct file *f, size_t off, size_t count)
{
	loff_t o = off;
	char *kaddr;
	ssize_t n;

	kaddr = kmap(p);
	n = f->f_op->read(f, (char __force __user *)kaddr + start, count, &o);
	kunmap(p);
	if (n < 0)
		return n;
	if (n != count)
		return -EFAULT;

	return 0;
}

/* copy data to a page in the receiver's pool */
static int kdbus_pool_copy_data(struct page *p, size_t start,
				const void __user *from, size_t count)
{
	unsigned long remain;
	char *kaddr;

	if (fault_in_pages_readable(from, count) < 0)
		return -EFAULT;

	kaddr = kmap_atomic(p);
	pagefault_disable();
	remain = __copy_from_user_inatomic(kaddr + start, from, count);
	pagefault_enable();
	kunmap_atomic(kaddr);
	if (remain > 0)
		return -EFAULT;

	cond_resched();
	return 0;
}

/* copy data to the receiver's pool */
static size_t kdbus_pool_copy(const struct kdbus_pool_slice *slice, size_t off,
			      const void __user *data, struct file *f_src,
			      size_t off_src, size_t len)
{
	struct file *f_dst = slice->pool->f;
	struct address_space *mapping = f_dst->f_mapping;
	const struct address_space_operations *aops = mapping->a_ops;
	unsigned long fpos = slice->off + off;
	unsigned long rem = len;
	size_t pos = 0;
	int ret = 0;

	BUG_ON(off + len > slice->size);

	while (rem > 0) {
		struct page *p;
		unsigned long o;
		unsigned long n;
		void *fsdata;
		int status;

		o = fpos & (PAGE_CACHE_SIZE - 1);
		n = min_t(unsigned long, PAGE_CACHE_SIZE - o, rem);

		status = aops->write_begin(f_dst, mapping, fpos, n, 0, &p,
					   &fsdata);
		if (status) {
			ret = -EFAULT;
			break;
		}

		if (data)
			ret = kdbus_pool_copy_data(p, o, data + pos, n);
		else
			ret = kdbus_pool_copy_file(p, o, f_src,
						   off_src + pos, n);
		mark_page_accessed(p);

		status = aops->write_end(f_dst, mapping, fpos, n, n, p, fsdata);

		if (ret < 0)
			break;
		if (status != n) {
			ret = -EFAULT;
			break;
		}

		pos += n;
		fpos += n;
		rem -= n;
	}

	return ret;
}

/**
 * kdbus_pool_slice_copy_user() - copy user memory to a slice
 * @slice:		The slice to write to
 * @off:		Offset in the slice to write to
 * @data:		User memory to copy from
 * @len:		Number of bytes to copy
 *
 * The offset was returned by the call to kdbus_pool_alloc_slice().
 * The user memory at @data will be copied to the @off in the allocated
 * slice in the pool.
 *
 * Return: the numbers of bytes copied, negative errno on failure.
 */
ssize_t
kdbus_pool_slice_copy_user(const struct kdbus_pool_slice *slice, size_t off,
			   const void __user *data, size_t len)
{
	return kdbus_pool_copy(slice, off, data, NULL, 0, len);
}

/**
 * kdbus_pool_slice_copy() - copy kernel memory to a slice
 * @slice:		The slice to write to
 * @off:		Offset in the slice to write to
 * @data:		Kernel memory to copy from
 * @len:		Number of bytes to copy
 *
 * The slice was returned by the call to kdbus_pool_alloc_slice().
 * The user memory at @data will be copied to the @off in the allocated
 * slice in the pool.
 *
 * Return: the numbers of bytes copied, negative errno on failure.
 */
ssize_t kdbus_pool_slice_copy(const struct kdbus_pool_slice *slice, size_t off,
			      const void *data, size_t len)
{
	mm_segment_t old_fs;
	ssize_t ret;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = kdbus_pool_copy(slice, off,
			      (const void __user *)data, NULL, 0, len);
	set_fs(old_fs);

	return ret;
}

/**
 * kdbus_pool_move_slice() - move memory from one pool into another one
 * @dst_pool:		The receiver's pool to copy to
 * @src_pool:		The receiver's pool to copy from
 * @slice:		Reference to the slice to copy from the source;
 *			updated with the newly allocated slice in the
 *			destination
 *
 * Move memory from one pool to another. Memory will be allocated in the
 * destination pool, the memory copied over, and the free()d in source
 * pool.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_pool_move_slice(struct kdbus_pool *dst_pool,
			  struct kdbus_pool *src_pool,
			  struct kdbus_pool_slice **slice)
{
	mm_segment_t old_fs;
	struct kdbus_pool_slice *slice_new;
	int ret;

	ret = kdbus_pool_slice_alloc(dst_pool, &slice_new, (*slice)->size);
	if (ret < 0)
		return ret;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = kdbus_pool_copy(slice_new, 0, NULL,
			      src_pool->f, (*slice)->off, (*slice)->size);
	set_fs(old_fs);
	if (ret < 0)
		goto exit_free;

	kdbus_pool_slice_free(*slice);

	*slice = slice_new;
	return 0;

exit_free:
	kdbus_pool_slice_free(slice_new);
	return ret;
}

/**
 * kdbus_pool_slice_flush() - flush dcache memory area of a slice
 * @slice:		The allocated slice to flush
 *
 * Dcache flushes are delayed to happen only right before the receiver
 * gets the new buffer area announced. The mapped buffer is always
 * read-only for the receiver, and only the area of the announced message
 * needs to be flushed.
 */
void kdbus_pool_slice_flush(const struct kdbus_pool_slice *slice)
{
#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	struct address_space *mapping = slice->pool->f->f_mapping;
	pgoff_t first = slice->off >> PAGE_CACHE_SHIFT;
	pgoff_t last = (slice->off + slice->size +
			PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	pgoff_t i;

	for (i = first; i < last; i++) {
		struct page *page;

		page = find_get_page(mapping, i);
		if (!page)
			continue;

		flush_dcache_page(page);
		put_page(page);
	}
#endif
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

	/* do not allow to map more than the size of the file */
	if ((vma->vm_end - vma->vm_start) > pool->size)
		return -EFAULT;

	/* replace the connection file with our shmem file */
	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = get_file(pool->f);

	return pool->f->f_op->mmap(pool->f, vma);
}
