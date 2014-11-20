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

#ifndef __KDBUS_METADATA_H
#define __KDBUS_METADATA_H

struct kdbus_meta;
struct kdbus_conn;
struct kdbus_domain;
struct kdbus_pool_slice;

struct kdbus_meta *kdbus_meta_new(void);
struct kdbus_meta *kdbus_meta_dup(const struct kdbus_meta *orig);
int kdbus_meta_append_data(struct kdbus_meta *meta, u64 type,
			   const void *buf, size_t len);
int kdbus_meta_append(struct kdbus_meta *meta,
		      struct kdbus_domain *domain,
		      struct kdbus_conn *conn,
		      u64 seq, u64 which);
void kdbus_meta_free(struct kdbus_meta *meta);
size_t kdbus_meta_size(const struct kdbus_meta *meta,
		       const struct kdbus_conn *conn_dst,
		       u64 *mask);
int kdbus_meta_write(const struct kdbus_meta *meta,
		     const struct kdbus_conn *conn_dst, u64 mask,
		     const struct kdbus_pool_slice *slice, size_t off);

#endif
