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

#ifndef __KDBUS_POOL_H
#define __KDBUS_POOL_H

/*
 * Messages sent with KDBUS_CMD_MSG_SEND are copied direcly by the
 * sending process into the receiver's pool. The receiver has provided
 * the memory and registered it with KDBUS_HELLO_POOL.
 *
 * Messages received with KDBUS_CMD_MSG_RECV just return a pointer
 * into the pool.
 *
 * The internally allocated memory needs to be returned by the receiver
 * with * KDBUS_CMD_MSG_RELEASE.
 */

/* The receiver-provided buffer managed as a pool of allocated and free
 * slices containing the queued messages. */
struct kdbus_pool {
	void __user *buf;		/* receiver-supplied buffer */
	size_t size;			/* size of buffer */
	size_t busy;			/* allocated size */

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
 * address. */
struct kdbus_slice {
	void __user *buf;		/* address of slice */
	size_t size;			/* size of slice */

	struct list_head entry;
	struct rb_node rb_node;
	bool free;

	struct page **pg;		/* pages mapped by the slice */
	unsigned int pg_n;		/* number of pages */
	size_t pg_off;			/* offset into the first page */
	void *pg_buf;			/* kernel address of mapped pages */
};

int kdbus_pool_init(struct kdbus_pool *pool, void __user *buf, size_t size);
void kdbus_pool_cleanup(struct kdbus_pool *pool);
bool kdbus_pool_is_anon_map(struct mm_struct *mm,
			    void __user *buf, size_t size);

void __user *kdbus_pool_alloc(struct kdbus_pool *pool, size_t size,
			      struct kdbus_slice **slice);
int kdbus_pool_free(struct kdbus_pool *pool, void __user *buf);

int kdbus_pool_slice_map(struct kdbus_slice *slice, struct task_struct *task);
void kdbus_pool_slice_unmap(struct kdbus_slice *slice);

int kdbus_pool_slice_copy(struct kdbus_slice *slice, size_t off,
			  void *buf, size_t size);
int kdbus_pool_slice_copy_user(struct kdbus_slice *slice, size_t off,
			       void __user *buf, size_t size);
#endif
