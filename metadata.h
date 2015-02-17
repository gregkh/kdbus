/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_METADATA_H
#define __KDBUS_METADATA_H

#include <linux/kernel.h>

struct kdbus_conn;
struct kdbus_kmsg;
struct kdbus_pool_slice;

struct kdbus_meta_proc;
struct kdbus_meta_conn;

extern unsigned long long kdbus_meta_attach_mask;

struct kdbus_meta_proc *kdbus_meta_proc_new(void);
struct kdbus_meta_proc *kdbus_meta_proc_ref(struct kdbus_meta_proc *mp);
struct kdbus_meta_proc *kdbus_meta_proc_unref(struct kdbus_meta_proc *mp);
int kdbus_meta_proc_collect(struct kdbus_meta_proc *mp, u64 what);
int kdbus_meta_proc_fake(struct kdbus_meta_proc *mp,
			 const struct kdbus_creds *creds,
			 const struct kdbus_pids *pids,
			 const char *seclabel);

struct kdbus_meta_conn *kdbus_meta_conn_new(void);
struct kdbus_meta_conn *kdbus_meta_conn_ref(struct kdbus_meta_conn *mc);
struct kdbus_meta_conn *kdbus_meta_conn_unref(struct kdbus_meta_conn *mc);
int kdbus_meta_conn_collect(struct kdbus_meta_conn *mc,
			    struct kdbus_kmsg *kmsg,
			    struct kdbus_conn *conn,
			    u64 what);

int kdbus_meta_export_prepare(struct kdbus_meta_proc *mp,
			      struct kdbus_meta_conn *mc,
			      u64 *mask, size_t *sz);
int kdbus_meta_export(struct kdbus_meta_proc *mp,
		      struct kdbus_meta_conn *mc,
		      u64 mask,
		      struct kdbus_pool_slice *slice,
		      off_t offset, size_t *real_size);
u64 kdbus_meta_calc_attach_flags(const struct kdbus_conn *sender,
				 const struct kdbus_conn *receiver);

#endif
