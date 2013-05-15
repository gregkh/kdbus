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

/* The pool has one or more slices, always spanning the entire size of the
 * pool.
 *
 * Every slice is an element in a list sorted by the buffer address, to
 * provide access to the next neighbor slice.
 *
 * Every slice is member in either the busy or the free tree. The free
 * tree is organized by slice size, the busy tree organized by buffer
 * address. */
struct kdbus_slice {
	void __user *buf;		/* address of slice */
	size_t size;			/* size of slice */

	struct list_head entry;
	struct rb_node rb_node;
	bool free;
};

static void __maybe_unused kdbus_pool_slices_dump(struct kdbus_pool *pool,
						  const char *str)
{
	struct kdbus_slice *s;

	printk("=== dump start '%s' pool=%p buf=%p size=%zu ===\n",
	       str, pool, pool->buf, pool->size);

	list_for_each_entry(s, &pool->slices, entry)
		printk("  slice=%p free=%u, buf=%p size=%zu\n",
		       s, s->free, s->buf, s->size);

	printk("=== dump end '%s' pool=%p ===\n", str, pool);
}

static struct kdbus_slice *kdbus_pool_slice_new(void *__user *buf, size_t size)
{
	struct kdbus_slice *slice;

	slice = kmalloc(sizeof(struct kdbus_slice), GFP_KERNEL);
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

	list_for_each_entry_safe(s, tmp, &pool->slices, entry) {
		list_del(&s->entry);
		kfree(s);
	}
}

/* allocate a message of the given size in the receiver's pool */
struct kdbus_msg __user *kdbus_pool_alloc(struct kdbus_pool *pool, size_t size)
{
	struct kdbus_slice *slice;

	slice = kdbus_pool_alloc_slice(pool, size);
	if (!slice)
		return NULL;

	return slice->buf;
}

/* free the allocated message */
int kdbus_pool_free(struct kdbus_pool *pool, struct kdbus_msg __user *msg)
{
	struct kdbus_slice *slice;

	if (!msg)
		return 0;

	slice = kdbus_pool_find_slice(pool, msg);
	if (!slice)
		return -ENXIO;

	kdbus_pool_free_slice(pool, slice);
	return 0;
}

/* unpin the receiver's pages */
void kdbus_pool_map_close(struct kdbus_pool_map *map)
{
	unsigned int i;

	for (i = 0; i < map->n; i++)
		put_page(map->pages[i]);
	kfree(map->pages);
}

/* pin the receiver's memory range/pages */
int kdbus_pool_map_open(struct kdbus_pool_map *map,
			struct task_struct *task,
			void __user *to, size_t len)
{
	unsigned int n;
	int have;
	unsigned long base;
	unsigned long addr;
	struct mm_struct *mm;

	memset(map, 0, sizeof(struct kdbus_pool_map));

	/* calculate the number of pages involved in the range */
	addr = (unsigned long)to;
	n = (addr + len - 1) / PAGE_SIZE - addr / PAGE_SIZE + 1;

	map->pages = kmalloc(n * sizeof(struct page *), GFP_KERNEL);
	if (!map->pages)
		return -ENOMEM;

	/* start address in our first page */
	base = addr & PAGE_MASK;
	map->pos = addr - base;

	/* pin the receiver's pool page(s); the task
	 * is pinned as long as the connection is open */
	mm = get_task_mm(task);
	if (!mm) {
		kdbus_pool_map_close(map);
		return -ESHUTDOWN;
	}
	down_read(&mm->mmap_sem);
	have = get_user_pages(task, mm, base, n,
			      true, false, map->pages, NULL);
	up_read(&mm->mmap_sem);
	mmput(mm);

	if (have < 0) {
		kdbus_pool_map_close(map);
		return have;
	}

	map->n = have;

	/* fewer pages than requested */
	if (map->n < n) {
		kdbus_pool_map_close(map);
		return -EFAULT;
	}

	return 0;
}

/* copy a memory range from the current user process page by
 * page into the pinned receiver's pool */
int kdbus_pool_map_write(struct kdbus_pool_map *map,
			 void __user *from, size_t len)
{
	int ret = 0;

	while (len > 0) {
		void *addr;
		size_t bytes;

		/* bytes to copy to remaining space of current page */
		bytes = min(PAGE_SIZE - map->pos, len);

		/* map, fill, unmap current page */
		addr = kmap(map->pages[map->cur]) + map->pos;

		/* a NULL from address just adds padding bytes for alignement */
		if (!from) {
			memset(addr, 0, bytes);
		} else {
			if (copy_from_user(addr, from, bytes))
				ret = -EFAULT;
		}

		kunmap(map->pages[map->cur]);
		if (ret < 0)
			break;

		/* add to pos, or move to next page */
		map->pos += bytes;
		if (map->pos == PAGE_SIZE) {
			map->pos = 0;
			map->cur++;
		}

		len -= bytes;
	}

	return ret;
}
