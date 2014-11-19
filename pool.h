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

#ifndef __KDBUS_POOL_H
#define __KDBUS_POOL_H

struct kdbus_pool;
struct kdbus_pool_slice;

struct kdbus_pool *kdbus_pool_new(const char *name, size_t size);
void kdbus_pool_free(struct kdbus_pool *pool);
size_t kdbus_pool_remain(struct kdbus_pool *pool);
int kdbus_pool_mmap(const struct kdbus_pool *pool, struct vm_area_struct *vma);
int kdbus_pool_release_offset(struct kdbus_pool *pool, size_t off);

struct kdbus_pool_slice *kdbus_pool_slice_alloc(struct kdbus_pool *pool,
						size_t size);
void kdbus_pool_slice_free(struct kdbus_pool_slice *slice);
struct kdbus_pool_slice *kdbus_pool_slice_find(struct kdbus_pool *pool,
					       size_t off);
int kdbus_pool_slice_move(struct kdbus_pool *src_pool,
			  struct kdbus_pool *dst_pool,
			  struct kdbus_pool_slice **slice);
size_t kdbus_pool_slice_offset(const struct kdbus_pool_slice *slice);
ssize_t kdbus_pool_slice_copy(const struct kdbus_pool_slice *slice, size_t off,
			      const void *data, size_t len);
ssize_t kdbus_pool_slice_copy_user(const struct kdbus_pool_slice *slice,
				   size_t off, const void __user *data,
				   size_t len);
void kdbus_pool_slice_flush(const struct kdbus_pool_slice *slice);

void kdbus_pool_slice_make_public(struct kdbus_pool_slice *slice);

#endif
