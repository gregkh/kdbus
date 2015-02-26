/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_POOL_H
#define __KDBUS_POOL_H

#include <linux/uio.h>

struct kdbus_pool;
struct kdbus_pool_slice;

struct kdbus_pool *kdbus_pool_new(const char *name, size_t size);
void kdbus_pool_free(struct kdbus_pool *pool);
void kdbus_pool_accounted(struct kdbus_pool *pool, size_t *size, size_t *acc);
int kdbus_pool_mmap(const struct kdbus_pool *pool, struct vm_area_struct *vma);
int kdbus_pool_release_offset(struct kdbus_pool *pool, size_t off);
void kdbus_pool_publish_empty(struct kdbus_pool *pool, u64 *off, u64 *size);

struct kdbus_pool_slice *kdbus_pool_slice_alloc(struct kdbus_pool *pool,
						size_t size, bool accounted);
void kdbus_pool_slice_release(struct kdbus_pool_slice *slice);
void kdbus_pool_slice_publish(struct kdbus_pool_slice *slice,
			      u64 *out_offset, u64 *out_size);
off_t kdbus_pool_slice_offset(const struct kdbus_pool_slice *slice);
size_t kdbus_pool_slice_size(const struct kdbus_pool_slice *slice);
int kdbus_pool_slice_copy(const struct kdbus_pool_slice *slice_dst,
			  const struct kdbus_pool_slice *slice_src);
ssize_t kdbus_pool_slice_copy_kvec(const struct kdbus_pool_slice *slice,
				   loff_t off, struct kvec *kvec,
				   size_t kvec_count, size_t total_len);
ssize_t kdbus_pool_slice_copy_iovec(const struct kdbus_pool_slice *slice,
				    loff_t off, struct iovec *iov,
				    size_t iov_count, size_t total_len);

#endif
