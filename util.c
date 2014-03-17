/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/ctype.h>
#include <linux/string.h>

#include "util.h"
#include "defaults.h"

/**
 * kdbus_sysname_valid() - validate names showing up in /proc, /sys and /dev
 * @name:		Name of domain, bus, endpoint
 *
 * Return: 0 if the given name is valid, otherwise negative errno
 */
int kdbus_sysname_is_valid(const char *name)
{
	unsigned int i;
	size_t len;

	len = strlen(name);
	if (len == 0)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		if (isalpha(name[i]))
			continue;
		if (isdigit(name[i]))
			continue;
		if (name[i] == '_')
			continue;
		if (i > 0 && i + 1 < len && strchr("-.", name[i]))
			continue;

		return -EINVAL;
	}

	return 0;
}

/**
 * kdbus_item_validate_name() - validate an item containing a name
 * @item:		Item to validate
 *
 * Return: zero on success or an negative error code on failure
 */
int kdbus_item_validate_name(const struct kdbus_item *item)
{
	if (item->size < KDBUS_ITEM_HEADER_SIZE + 2)
		return -EINVAL;

	if (item->size > KDBUS_ITEM_HEADER_SIZE +
			 KDBUS_SYSNAME_MAX_LEN + 1)
		return -ENAMETOOLONG;

	if (!kdbus_item_validate_nul(item))
		return -EINVAL;

	return kdbus_sysname_is_valid(item->str);
}
