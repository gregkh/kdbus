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

#include <linux/ctype.h>
#include <linux/string.h>

#include "defaults.h"
#include "item.h"
#include "util.h"

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
