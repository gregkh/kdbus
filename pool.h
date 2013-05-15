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
	size_t size;			/* size of buffer  */

	struct list_head slices;	/* all slices sorted by address */
	struct rb_root slices_busy;	/* tree of allocated slices */
	struct rb_root slices_free;	/* tree of free slices */
};

/* State of a mapped range on the pool while writing chunks of data
 * to it from the sender.  */
struct kdbus_pool_map {
	struct page **pages;	/* array of pages representign the pool */
	unsigned int n;		/* number pf pages in the array */
	unsigned long cur;	/* current page we write to */
	unsigned long pos;	/* position in current page we write to */
};

int kdbus_pool_init(struct kdbus_pool *pool, void __user *buf, size_t size);
void kdbus_pool_cleanup(struct kdbus_pool *pool);

struct kdbus_msg __user *kdbus_pool_alloc(struct kdbus_pool *pool, size_t size);
int kdbus_pool_free(struct kdbus_pool *pool, struct kdbus_msg __user *msg);

void kdbus_pool_map_close(struct kdbus_pool_map *map);
int kdbus_pool_map_open(struct kdbus_pool_map *map,
			struct task_struct *task,
			void __user *to, size_t len);
int kdbus_pool_map_write(struct kdbus_pool_map *map,
			   void __user *from, size_t len);
#endif
