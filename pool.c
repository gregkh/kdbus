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
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#include "pool.h"
#include "message.h"

/* allocate a slot on the given size in the receiver's pool */
struct kdbus_msg __user *
kdbus_pool_alloc(struct kdbus_pool *buf, size_t len)
{
	size_t pos;

	pos = KDBUS_ALIGN8(buf->pos);
	if (pos + len > buf->size)
		return NULL;

	buf->pos = pos + len;
	buf->users++;

	return buf->buf + pos;
}

/* free the allocated slot */
void kdbus_pool_free(struct kdbus_pool *buf, struct kdbus_msg __user *msg)
{
	if (!msg)
		return;

	BUG_ON(buf->users == 0);

	/* FIXME: dumbest possible version of an allocator: just reset the pool
	 * when it is empty; replace with rbtree/slice/list allocator */
	if (--buf->users == 0)
		buf->pos = 0;
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

	memset(map, 0, sizeof(struct kdbus_pool));

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

		/* bytes copy to remaining space of current page */
		bytes = min(PAGE_SIZE - map->pos, len);

		/* map, fill, unmap current page */
		addr = kmap(map->pages[map->cur]) + map->pos;
		if (copy_from_user(addr, from, bytes))
			ret = -EFAULT;
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
