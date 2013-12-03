/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_METADATA_H
#define __KDBUS_METADATA_H

/**
 * kdbus_meta - metadata buffer
 * @attached		flags for already attached data
 * @data		allocated buffer
 * @size		number of bytes used
 * @allocated size	size of buffer
 * @src_names		list of \0-separated well-known names
 * src_names_len	length of list
 *
 * Used to collect and store connection metadata in a pre-compiled
 * buffer containing struct kdbus_item.
 */
struct kdbus_meta {
	u64 attached;
	struct kdbus_item *data;
	size_t size;
	size_t allocated_size;

	const char *src_names;
	size_t src_names_len;
};

struct kdbus_conn;

int kdbus_meta_append(struct kdbus_meta *meta,
		      struct kdbus_conn *conn,
		      u64 which);
void kdbus_meta_free(struct kdbus_meta *meta);
#endif
