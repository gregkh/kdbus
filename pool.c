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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/rbtree.h>
#include <linux/file.h>
#include <linux/shmem_fs.h>
#include <linux/aio.h>

#include "pool.h"
#include "message.h"

/*
 * Messages sent with KDBUS_CMD_MSG_SEND are copied direcly by the
 * sending process into the receiver's pool.
 *
 * Messages received with KDBUS_CMD_MSG_RECV just return the offset
 * to the data placed in the pool.
 *
 * The internally allocated memory needs to be returned by the receiver
 * with KDBUS_CMD_MSG_RELEASE.
 */

/* The receiver's buffer, managed as a pool of allocated and free
 * slices containing the queued messages. */
struct kdbus_pool {
	struct file *f;			/* shmem file */
	size_t size;			/* size of file  */
	size_t busy;			/* currently allocated size */

	struct list_head slices;	/* all slices sorted by address */
	struct rb_root slices_busy;	/* tree of allocated slices */
	struct rb_root slices_free;	/* tree of free slices */
};

/* The pool has one or more slices, always spanning the entire size of the
 * pool.
 *
 * Every slice is an element in a list sorted by the buffer address, to
 * provide access to the next neighbor slice.
 *
 * Every slice is member in either the busy or the free tree. The free
 * tree is organized by slice size, the busy tree organized by buffer
 * offset. */
struct kdbus_slice {
	size_t off;			/* offset of slice */
	size_t size;			/* size of slice */

	struct list_head entry;
	struct rb_node rb_node;
	bool free;
};

static void __maybe_unused kdbus_pool_slices_dump(struct kdbus_pool *pool,
						  const char *str)
{
	struct kdbus_slice *s;

	pr_info("=== dump start '%s' pool=%p size=%zu ===\n",
		str, pool, pool->size);

	list_for_each_entry(s, &pool->slices, entry)
		pr_info("  slice=%p free=%u, off=%zu size=%zu\n",
			s, s->free, s->off, s->size);

	pr_info("=== dump end '%s' pool=%p ===\n", str, pool);
}

static struct kdbus_slice *kdbus_pool_slice_new(size_t off, size_t size)
{
	struct kdbus_slice *slice;

	slice = kzalloc(sizeof(struct kdbus_slice), GFP_KERNEL);
	if (!slice)
		return NULL;

	slice->off = off;
	slice->size = size;
	slice->free = true;
	return slice;
}

/* insert a slice into the free tree */
static void kdbus_pool_add_free_slice(struct kdbus_pool *pool,
				      struct kdbus_slice *slice)
{
	struct rb_node **n;
	struct rb_node *pn = NULL;

	n = &pool->slices_free.rb_node;
	while (*n) {
		struct kdbus_slice *pslice;

		pn = *n;
		pslice = rb_entry(pn, struct kdbus_slice, rb_node);
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
				      struct kdbus_slice *slice)
{
	struct rb_node **n;
	struct rb_node *pn = NULL;

	n = &pool->slices_busy.rb_node;
	while (*n) {
		struct kdbus_slice *pslice;

		pn = *n;
		pslice = rb_entry(pn, struct kdbus_slice, rb_node);
		if (slice->off < pslice->off)
			n = &pn->rb_left;
		else if (slice->off > pslice->off)
			n = &pn->rb_right;
	}

	rb_link_node(&slice->rb_node, pn, n);
	rb_insert_color(&slice->rb_node, &pool->slices_busy);
}

/* find a slice by its pool offset */
static struct kdbus_slice *kdbus_pool_find_slice(struct kdbus_pool *pool,
						 size_t off)
{
	struct rb_node *n;

	n = pool->slices_busy.rb_node;
	while (n) {
		struct kdbus_slice *s;

		s = rb_entry(n, struct kdbus_slice, rb_node);
		if (off < s->off)
			n = n->rb_left;
		else if (off > s->off)
			n = n->rb_right;
		else
			return s;
	}

	return NULL;
}

/* allocate a slice from the pool with the given size */
static int kdbus_pool_alloc_slice(struct kdbus_pool *pool,
				  size_t size, struct kdbus_slice **slice)
{
	size_t slice_size = KDBUS_ALIGN8(size);
	struct rb_node *n;
	struct kdbus_slice *s;
	struct rb_node *found = NULL;

	/* search a free slice with the closest matching size */
	n = pool->slices_free.rb_node;
	while (n) {
		s = rb_entry(n, struct kdbus_slice, rb_node);
		if (slice_size < s->size) {
			found = n;
			n = n->rb_left;
		} else if (slice_size > s->size)
			n = n->rb_right;
		else {
			found = n;
			break;
		}
	}

	/* no slice with the minimum size found in the pool */
	if (!found)
		return -ENOBUFS;

	/* no exact match, use the closest one */
	if (!n)
		s = rb_entry(found, struct kdbus_slice, rb_node);

	/* move slice from free to the busy tree */
	rb_erase(found, &pool->slices_free);
	kdbus_pool_add_busy_slice(pool, s);

	/* we got a slice larger than what we asked for? */
	if (s->size > slice_size) {
		struct kdbus_slice *s_new;

		/* split-off the remainder of the size to its own slice */
		s_new = kdbus_pool_slice_new(s->off + slice_size,
					     s->size - slice_size);
		if (!s_new)
			return -ENOMEM;

		list_add(&s_new->entry, &s->entry);
		kdbus_pool_add_free_slice(pool, s_new);

		/* adjust our size now that we split-off another slice */
		s->size = slice_size;
	}

	s->free = false;
	pool->busy += s->size;
	*slice = s;
	return 0;
}

/* return an allocated slice back to the pool */
static void kdbus_pool_free_slice(struct kdbus_pool *pool,
				  struct kdbus_slice *slice)
{
	rb_erase(&slice->rb_node, &pool->slices_busy);
	pool->busy -= slice->size;

	/* merge with the next free slice */
	if (!list_is_last(&slice->entry, &pool->slices)) {
		struct kdbus_slice *s;

		s = list_entry(slice->entry.next, struct kdbus_slice, entry);
		if (s->free) {
			rb_erase(&s->rb_node, &pool->slices_free);
			list_del(&s->entry);
			slice->size += s->size;
			kfree(s);
		}
	}

	/* merge with previous free slice */
	if (pool->slices.next != &slice->entry) {
		struct kdbus_slice *s;

		s = list_entry(slice->entry.prev, struct kdbus_slice, entry);
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
}

int kdbus_pool_init(struct kdbus_pool **pool, size_t size)
{
	struct kdbus_pool *p;
	struct file *f;
	struct kdbus_slice *s;
	int ret;

	p = kzalloc(sizeof(struct kdbus_pool), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	f = shmem_file_setup("kdbus-pool", size, 0);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto exit_free_p;
	}

	/* allocate first slice spanning the entire pool */
	s = kdbus_pool_slice_new(0, size);
	if (!s) {
		ret = -ENOMEM;
		goto exit_put_shmem;
	}

	p->f = f;
	p->size = size;
	p->busy = 0;
	p->slices_free = RB_ROOT;
	p->slices_busy = RB_ROOT;

	INIT_LIST_HEAD(&p->slices);
	list_add(&s->entry, &p->slices);

	kdbus_pool_add_free_slice(p, s);
	*pool = p;
	return 0;

exit_put_shmem:
	fput(f);
exit_free_p:
	kfree(p);
	return ret;
}

void kdbus_pool_cleanup(struct kdbus_pool *pool)
{
	struct kdbus_slice *s, *tmp;

	if (!pool)
		return;

	list_for_each_entry_safe(s, tmp, &pool->slices, entry) {
		list_del(&s->entry);
		kfree(s);
	}

	fput(pool->f);
	kfree(pool);
}

size_t kdbus_pool_remain(const struct kdbus_pool *pool)
{
	return pool->size - pool->busy;
}

/* allocate a message of the given size in the receiver's pool */
int kdbus_pool_alloc(struct kdbus_pool *pool, size_t size, size_t *off)
{
	struct kdbus_slice *s;
	int ret;

	ret = kdbus_pool_alloc_slice(pool, size, &s);
	if (ret < 0)
		return ret;

	*off = s->off;
	return 0;
}

/* free the allocated message */
int kdbus_pool_free(struct kdbus_pool *pool, size_t off)
{
	struct kdbus_slice *slice;

	if (!pool)
		return 0;

	if (off >= pool->size)
		return -EINVAL;

	slice = kdbus_pool_find_slice(pool, off);
	if (!slice)
		return -ENXIO;

	kdbus_pool_free_slice(pool, slice);
	return 0;
}

/* write to the receiver's shmem file */
ssize_t kdbus_pool_write_user(const struct kdbus_pool *pool, size_t off,
			      void __user *data, size_t len)
{
	loff_t o = off;

	return pool->f->f_op->write(pool->f, data, len, &o);
}

ssize_t kdbus_pool_write(const struct kdbus_pool *pool, size_t off,
			 void *data, size_t len)
{
	loff_t o = off;
	mm_segment_t old_fs;
	void __user *p;
	ssize_t ret;

	old_fs = get_fs();
	set_fs(get_ds());

	p = (void __force __user *)data;
	ret = pool->f->f_op->write(pool->f, p, len, &o);

	set_fs(old_fs);
	return ret;
}

/* map the shmem file for the receiver */
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
