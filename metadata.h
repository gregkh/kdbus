/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 * Copyright (C) 2014 Djalal Harouni
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

extern unsigned long long kdbus_meta_attach_mask;

struct kdbus_meta *kdbus_meta_new(void);
struct kdbus_meta *kdbus_meta_ref(struct kdbus_meta *meta);
struct kdbus_meta *kdbus_meta_unref(struct kdbus_meta *meta);

int kdbus_meta_add_current(struct kdbus_meta *meta,
			   u64 seq, u64 which);
int kdbus_meta_add_conn_info(struct kdbus_meta *meta,
			     struct kdbus_conn *conn_src);
int kdbus_meta_add_fake(struct kdbus_meta *meta,
			const struct kdbus_creds *creds,
			const struct kdbus_pids *pids,
			const char *seclabel);
struct kdbus_item *kdbus_meta_export(const struct kdbus_meta *meta,
				     u64 mask, size_t *sz);
u64 kdbus_meta_calc_attach_flags(const struct kdbus_conn *sender,
				 const struct kdbus_conn *receiver);

#endif
