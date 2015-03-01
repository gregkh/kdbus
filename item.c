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

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/string.h>

#include "item.h"
#include "limits.h"
#include "util.h"

/*
 * This verifies the string at position @str with size @size is properly
 * zero-terminated and does not contain a 0-byte but at the end.
 */
static bool kdbus_str_valid(const char *str, size_t size)
{
	return size > 0 && memchr(str, '\0', size) == str + size - 1;
}

/**
 * kdbus_item_validate_name() - validate an item containing a name
 * @item:		Item to validate
 *
 * Return: zero on success or an negative error code on failure
 */
int kdbus_item_validate_name(const struct kdbus_item *item)
{
	const char *name = item->str;
	unsigned int i;
	size_t len;

	if (item->size < KDBUS_ITEM_HEADER_SIZE + 2)
		return -EINVAL;

	if (item->size > KDBUS_ITEM_HEADER_SIZE +
			 KDBUS_SYSNAME_MAX_LEN + 1)
		return -ENAMETOOLONG;

	if (!kdbus_str_valid(name, KDBUS_ITEM_PAYLOAD_SIZE(item)))
		return -EINVAL;

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
		if (i > 0 && i + 1 < len && (name[i] == '-' || name[i] == '.'))
			continue;

		return -EINVAL;
	}

	return 0;
}

/**
 * kdbus_item_validate() - validate a single item
 * @item:	item to validate
 *
 * Return: 0 if item is valid, negative error code if not.
 */
int kdbus_item_validate(const struct kdbus_item *item)
{
	size_t payload_size = KDBUS_ITEM_PAYLOAD_SIZE(item);
	size_t l;
	int ret;

	BUILD_BUG_ON(KDBUS_ITEM_HEADER_SIZE !=
		     sizeof(struct kdbus_item_header));

	if (item->size < KDBUS_ITEM_HEADER_SIZE)
		return -EINVAL;

	switch (item->type) {
	case KDBUS_ITEM_NEGOTIATE:
		if (payload_size % sizeof(u64) != 0)
			return -EINVAL;
		break;

	case KDBUS_ITEM_PAYLOAD_VEC:
		if (payload_size != sizeof(struct kdbus_vec))
			return -EINVAL;
		if (item->vec.size == 0 || item->vec.size > SIZE_MAX)
			return -EINVAL;
		break;

	case KDBUS_ITEM_PAYLOAD_OFF:
		if (payload_size != sizeof(struct kdbus_vec))
			return -EINVAL;
		if (item->vec.size == 0 || item->vec.size > SIZE_MAX)
			return -EINVAL;
		break;

	case KDBUS_ITEM_PAYLOAD_MEMFD:
		if (payload_size != sizeof(struct kdbus_memfd))
			return -EINVAL;
		if (item->memfd.size == 0 || item->memfd.size > SIZE_MAX)
			return -EINVAL;
		if (item->memfd.fd < 0)
			return -EBADF;
		break;

	case KDBUS_ITEM_FDS:
		if (payload_size % sizeof(int) != 0)
			return -EINVAL;
		break;

	case KDBUS_ITEM_CANCEL_FD:
		if (payload_size != sizeof(int))
			return -EINVAL;
		break;

	case KDBUS_ITEM_BLOOM_PARAMETER:
		if (payload_size != sizeof(struct kdbus_bloom_parameter))
			return -EINVAL;
		break;

	case KDBUS_ITEM_BLOOM_FILTER:
		/* followed by the bloom-mask, depends on the bloom-size */
		if (payload_size < sizeof(struct kdbus_bloom_filter))
			return -EINVAL;
		break;

	case KDBUS_ITEM_BLOOM_MASK:
		/* size depends on bloom-size of bus */
		break;

	case KDBUS_ITEM_CONN_DESCRIPTION:
	case KDBUS_ITEM_MAKE_NAME:
		ret = kdbus_item_validate_name(item);
		if (ret < 0)
			return ret;
		break;

	case KDBUS_ITEM_ATTACH_FLAGS_SEND:
	case KDBUS_ITEM_ATTACH_FLAGS_RECV:
	case KDBUS_ITEM_ID:
		if (payload_size != sizeof(u64))
			return -EINVAL;
		break;

	case KDBUS_ITEM_TIMESTAMP:
		if (payload_size != sizeof(struct kdbus_timestamp))
			return -EINVAL;
		break;

	case KDBUS_ITEM_CREDS:
		if (payload_size != sizeof(struct kdbus_creds))
			return -EINVAL;
		break;

	case KDBUS_ITEM_AUXGROUPS:
		if (payload_size % sizeof(u32) != 0)
			return -EINVAL;
		break;

	case KDBUS_ITEM_NAME:
	case KDBUS_ITEM_DST_NAME:
	case KDBUS_ITEM_PID_COMM:
	case KDBUS_ITEM_TID_COMM:
	case KDBUS_ITEM_EXE:
	case KDBUS_ITEM_CMDLINE:
	case KDBUS_ITEM_CGROUP:
	case KDBUS_ITEM_SECLABEL:
		if (!kdbus_str_valid(item->str, payload_size))
			return -EINVAL;
		break;

	case KDBUS_ITEM_CAPS:
		if (payload_size < sizeof(u32))
			return -EINVAL;
		if (payload_size < sizeof(u32) +
		    4 * CAP_TO_INDEX(item->caps.last_cap) * sizeof(u32))
			return -EINVAL;
		break;

	case KDBUS_ITEM_AUDIT:
		if (payload_size != sizeof(struct kdbus_audit))
			return -EINVAL;
		break;

	case KDBUS_ITEM_POLICY_ACCESS:
		if (payload_size != sizeof(struct kdbus_policy_access))
			return -EINVAL;
		break;

	case KDBUS_ITEM_NAME_ADD:
	case KDBUS_ITEM_NAME_REMOVE:
	case KDBUS_ITEM_NAME_CHANGE:
		if (payload_size < sizeof(struct kdbus_notify_name_change))
			return -EINVAL;
		l = payload_size - offsetof(struct kdbus_notify_name_change,
					    name);
		if (l > 0 && !kdbus_str_valid(item->name_change.name, l))
			return -EINVAL;
		break;

	case KDBUS_ITEM_ID_ADD:
	case KDBUS_ITEM_ID_REMOVE:
		if (payload_size != sizeof(struct kdbus_notify_id_change))
			return -EINVAL;
		break;

	case KDBUS_ITEM_REPLY_TIMEOUT:
	case KDBUS_ITEM_REPLY_DEAD:
		if (payload_size != 0)
			return -EINVAL;
		break;

	default:
		break;
	}

	return 0;
}

/**
 * kdbus_items_validate() - validate items passed by user-space
 * @items:		items to validate
 * @items_size:		number of items
 *
 * This verifies that the passed items pointer is consistent and valid.
 * Furthermore, each item is checked for:
 *  - valid "size" value
 *  - payload is of expected type
 *  - payload is fully included in the item
 *  - string payloads are zero-terminated
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_items_validate(const struct kdbus_item *items, size_t items_size)
{
	const struct kdbus_item *item;
	int ret;

	KDBUS_ITEMS_FOREACH(item, items, items_size) {
		if (!KDBUS_ITEM_VALID(item, items, items_size))
			return -EINVAL;

		ret = kdbus_item_validate(item);
		if (ret < 0)
			return ret;
	}

	if (!KDBUS_ITEMS_END(item, items, items_size))
		return -EINVAL;

	return 0;
}

static struct kdbus_item *kdbus_items_get(const struct kdbus_item *items,
					  size_t items_size,
					  unsigned int item_type)
{
	const struct kdbus_item *iter, *found = NULL;

	KDBUS_ITEMS_FOREACH(iter, items, items_size) {
		if (iter->type == item_type) {
			if (found)
				return ERR_PTR(-EEXIST);
			found = iter;
		}
	}

	return (struct kdbus_item *)found ? : ERR_PTR(-EBADMSG);
}

/**
 * kdbus_items_get_str() - get string from a list of items
 * @items:		The items to walk
 * @items_size:		The size of all items
 * @item_type:		The item type to look for
 *
 * This function walks a list of items and searches for items of type
 * @item_type. If it finds exactly one such item, @str_ret will be set to
 * the .str member of the item.
 *
 * Return: the string, if the item was found exactly once, ERR_PTR(-EEXIST)
 * if the item was found more than once, and ERR_PTR(-EBADMSG) if there was
 * no item of the given type.
 */
const char *kdbus_items_get_str(const struct kdbus_item *items,
				size_t items_size,
				unsigned int item_type)
{
	const struct kdbus_item *item;

	item = kdbus_items_get(items, items_size, item_type);
	return IS_ERR(item) ? ERR_CAST(item) : item->str;
}

/**
 * kdbus_item_set() - Set item content
 * @item:	The item to modify
 * @type:	The item type to set (KDBUS_ITEM_*)
 * @data:	Data to copy to item->data, may be %NULL
 * @len:	Number of bytes in @data
 *
 * This sets type, size and data fields of an item. If @data is NULL, the data
 * memory is cleared.
 *
 * Note that you must align your @data memory to 8 bytes. Trailing padding (in
 * case @len is not 8byte aligned) is cleared by this call.
 *
 * Returns: Pointer to the following item.
 */
struct kdbus_item *kdbus_item_set(struct kdbus_item *item, u64 type,
				  const void *data, size_t len)
{
	item->type = type;
	item->size = KDBUS_ITEM_HEADER_SIZE + len;

	if (data) {
		memcpy(item->data, data, len);
		memset(item->data + len, 0, KDBUS_ALIGN8(len) - len);
	} else {
		memset(item->data, 0, KDBUS_ALIGN8(len));
	}

	return KDBUS_ITEM_NEXT(item);
}
