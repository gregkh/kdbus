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

#include "pool.h"
#include "message.h"

static void __maybe_unused kdbus_pool_slices_dump(struct kdbus_pool *pool,
						  const char *str)
{
	struct kdbus_slice *s;

	pr_info("=== dump start '%s' pool=%p buf=%p size=%zu ===\n",
		str, pool, pool->buf, pool->size);

	list_for_each_entry(s, &pool->slices, entry)
		pr_info("  slice=%p free=%u, buf=%p size=%zu\n",
		        s, s->free, s->buf, s->size);

	pr_info("=== dump end '%s' pool=%p ===\n", str, pool);
}

static struct kdbus_slice *kdbus_pool_slice_new(void *__user *buf, size_t size)
{
	struct kdbus_slice *slice;

	slice = kzalloc(sizeof(struct kdbus_slice), GFP_KERNEL);
	if (!slice)
		return NULL;

	slice->buf = buf;
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
		if (slice->buf < pslice->buf)
			n = &pn->rb_left;
		else if (slice->buf > pslice->buf)
			n = &pn->rb_right;
	}

	rb_link_node(&slice->rb_node, pn, n);
	rb_insert_color(&slice->rb_node, &pool->slices_busy);
}

/* find a slice by its pool buffer address */
static struct kdbus_slice *kdbus_pool_find_slice(struct kdbus_pool *pool,
						 void __user *buf)
{
	struct rb_node *n;

	n = pool->slices_busy.rb_node;
	while (n) {
		struct kdbus_slice *s;

		s = rb_entry(n, struct kdbus_slice, rb_node);
		if (buf < s->buf)
			n = n->rb_left;
		else if (buf > s->buf)
			n = n->rb_right;
		else
			return s;
	}

	return NULL;
}

/* allocate a slice from the pool with the given size */
static struct kdbus_slice *kdbus_pool_alloc_slice(struct kdbus_pool *pool,
						  size_t size)
{
	size_t slice_size = KDBUS_ALIGN8(size);
	struct rb_node *n;
	struct kdbus_slice *slice;
	struct rb_node *found = NULL;

	/* search a free slice with the closest matching size */
	n = pool->slices_free.rb_node;
	while (n) {
		slice = rb_entry(n, struct kdbus_slice, rb_node);
		if (slice_size < slice->size) {
			found = n;
			n = n->rb_left;
		} else if (slice_size > slice->size)
			n = n->rb_right;
		else {
			found = n;
			break;
		}
	}

	/* no slice with the minimum size found in the pool */
	if (!found)
		return NULL;

	/* no exact match, use the closest one */
	if (!n)
		slice = rb_entry(found, struct kdbus_slice, rb_node);

	/* move slice from free to the busy tree */
	rb_erase(found, &pool->slices_free);
	kdbus_pool_add_busy_slice(pool, slice);

	/* we got a slice larger than what we asked for? */
	if (slice->size > slice_size) {
		struct kdbus_slice *s;

		/* split-off the remainder of the size to its own slice */
		s = kdbus_pool_slice_new(slice->buf + slice_size,
					 slice->size - slice_size);
		if (!s)
			return NULL;

		list_add(&s->entry, &slice->entry);
		kdbus_pool_add_free_slice(pool, s);

		/* adjust our size now that we split-off another slice */
		slice->size = slice_size;
	}

	slice->free = false;
	return slice;
}

/* return an allocated slice back to the pool */
static void kdbus_pool_free_slice(struct kdbus_pool *pool,
				  struct kdbus_slice *slice)
{
	rb_erase(&slice->rb_node, &pool->slices_busy);

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

int kdbus_pool_init(struct kdbus_pool *pool, void __user *buf, size_t size)
{
	struct kdbus_slice *s;

	pool->buf = buf;
	pool->size = size;
	pool->slices_free = RB_ROOT;
	pool->slices_busy = RB_ROOT;

	/* allocate first slice spanning the entire pool */
	s = kdbus_pool_slice_new(buf, size);
	if (!s)
		return -ENOMEM;

	INIT_LIST_HEAD(&pool->slices);
	list_add(&s->entry, &pool->slices);

	kdbus_pool_add_free_slice(pool, s);
	return 0;
}

void kdbus_pool_cleanup(struct kdbus_pool *pool)
{
	struct kdbus_slice *s, *tmp;

	if (!pool->buf)
		return;

	list_for_each_entry_safe(s, tmp, &pool->slices, entry) {
		list_del(&s->entry);
		kfree(s);
	}
}

/* allocate a message of the given size in the receiver's pool */
void __user *kdbus_pool_alloc(struct kdbus_pool *pool, size_t size,
			     struct kdbus_slice **slice)
{
	struct kdbus_slice *s;

	s = kdbus_pool_alloc_slice(pool, size);
	if (!s)
		return NULL;

	*slice = s;
	return s->buf;
}

/* free the allocated message */
int kdbus_pool_free(struct kdbus_pool *pool, void __user *buf)
{
	struct kdbus_slice *slice;

	if (!buf)
		return 0;

	slice = kdbus_pool_find_slice(pool, buf);
	if (!slice)
		return -ENXIO;

	kdbus_pool_free_slice(pool, slice);
	return 0;
}

/* unpin the receiver's pages */
void kdbus_pool_slice_unmap(struct kdbus_slice *slice)
{
	unsigned int i;

	if (!slice)
		return;

	vunmap(slice->pg_buf);
	slice->pg_buf = NULL;

	for (i = 0; i < slice->pg_n; i++)
		put_page(slice->pg[i]);
	kfree(slice->pg);

	slice->pg_n = 0;
	slice->pg = NULL;
}

/* pin the receiver's memory range/pages */
int kdbus_pool_slice_map(struct kdbus_slice *slice, struct task_struct *task)
{
	unsigned int n;
	int have;
	unsigned long base;
	unsigned long addr;
	struct mm_struct *mm;

	/* calculate the number of pages involved in the range */
	addr = (unsigned long)slice->buf;
	n = (addr + slice->size - 1) / PAGE_SIZE - addr / PAGE_SIZE + 1;

	slice->pg = kmalloc(n * sizeof(struct page *), GFP_KERNEL);
	if (!slice->pg)
		return -ENOMEM;

	/* start address in our first page */
	base = addr & PAGE_MASK;
	slice->pg_off = addr - base;

	/* pin the receiver's pool page(s); the task
	 * is pinned as long as the connection is open */
	mm = get_task_mm(task);
	if (!mm) {
		kdbus_pool_slice_unmap(slice);
		return -ESHUTDOWN;
	}
	down_read(&mm->mmap_sem);
	have = get_user_pages(task, mm, base, n,
			      true, false, slice->pg, NULL);
	up_read(&mm->mmap_sem);
	mmput(mm);

	if (have < 0) {
		kdbus_pool_slice_unmap(slice);
		return have;
	}

	slice->pg_n = have;

	/* fewer pages than requested */
	if (slice->pg_n < n) {
		kdbus_pool_slice_unmap(slice);
		return -EFAULT;
	}

	/* map the slice so we can access it */
	slice->pg_buf = vmap(slice->pg, slice->pg_n, 0, PAGE_KERNEL);
	if (!slice->pg_buf) {
		kdbus_pool_slice_unmap(slice);
		return -EFAULT;
	}

	return 0;
}

/* copy a memory range to a slice in the receiver's pool */
int kdbus_pool_slice_copy(struct kdbus_slice *slice, size_t off,
			  void *buf, size_t size)
{
	memcpy(slice->pg_buf + slice->pg_off + off, buf, size);
	return 0;
}

/* copy a user memory range to a slice in the receiver's pool */
int kdbus_pool_slice_copy_user(struct kdbus_slice *slice, size_t off,
			       void __user *buf, size_t size)
{
	/* a NULL from address just adds padding bytes for alignement */
	if (!buf) {
		memset(slice->pg_buf + slice->pg_off + off, 0, size);
		return 0;
	}

	if (copy_from_user(slice->pg_buf + slice->pg_off + off, buf, size))
		return -EFAULT;

	return 0;
}
