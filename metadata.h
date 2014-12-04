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

int kdbus_meta_collect(struct kdbus_meta *meta,
		       u64 seq, u64 which);
int kdbus_meta_collect_src(struct kdbus_meta *meta,
			   struct kdbus_conn *conn_src);
int kdbus_meta_collect_dst(struct kdbus_meta *meta, u64 seq,
			   const struct kdbus_conn *conn_dst);
int kdbus_meta_fake(struct kdbus_meta *meta,
		    const struct kdbus_creds *creds,
		    const struct kdbus_pids *pids,
		    const char *seclabel);
int kdbus_meta_export(const struct kdbus_meta *meta,
		      struct kdbus_conn *conn_dst,
		      u64 mask, u8 **buf, size_t *size);

/**
 * kdbus_meta_set_attach_flags() - Set the attach flags
 * @flags		Attach flags provided by userspace
 * @attach_flags	A pointer where to store the valid attach flags
 *
 * Code that sets the meta attach flags must call this function to
 * validate the provided flags.
 *
 * Return: 0 on success, negative error on failure.
 */
static inline int kdbus_meta_set_attach_flags(u64 flags,
					      u64 *attach_flags)
{
	/* 'any' degrades to 'all' for compatibility */
	if (flags == _KDBUS_ATTACH_ANY)
		flags = _KDBUS_ATTACH_ALL;

	/* reject unknown attach flags */
	if (flags & ~_KDBUS_ATTACH_ALL)
		return -EINVAL;

	*attach_flags = flags;

	return 0;
}

#endif
