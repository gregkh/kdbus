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

#ifndef __KDBUS_INTERNAL_H
#define __KDBUS_INTERNAL_H

#include "kdbus.h"

/* limits enforced by the interfaces */
#define KDBUS_MSG_MAX_SIZE		SZ_8K		/* maximum size of message header and items */
#define KDBUS_MSG_MAX_ITEMS		128		/* maximum number of message items */
#define KDBUS_MSG_MAX_FDS		256		/* maximum number of passed file descriptors */
#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE	SZ_8M		/* maximum message payload size */

#define KDBUS_NAME_MAX_LEN		255		/* maximum length of well-known bus name */

#define KDBUS_MAKE_MAX_LEN		63		/* maximum length of bus, ns, ep name */
#define KDBUS_MAKE_MAX_SIZE		SZ_32K		/* maximum size of make data */

#define KDBUS_HELLO_MAX_SIZE		SZ_32K		/* maximum size of hello data */
#define KDBUS_MATCH_MAX_SIZE		SZ_32K		/* maximum size of match data */
#define KDBUS_POLICY_MAX_SIZE		SZ_32K		/* maximum size of policy data */

#define KDBUS_CONN_MAX_MSGS		64		/* maximum number of queued messages on the bus */
#define KDBUS_CONN_MAX_NAMES		64		/* maximum number of well-known names */
#define KDBUS_CONN_MAX_ALLOCATED_BYTES	SZ_64K		/* maximum number of allocated bytes on the bus */

/* all exported addresses are 64 bit */
#define KDBUS_PTR(addr) ((void __user *)(uintptr_t)(addr))

/* all exported sizes are 64 bit and data aligned to 64 bit */
#define KDBUS_ALIGN8(s) ALIGN((s), 8)
#define KDBUS_IS_ALIGNED8(s) (IS_ALIGNED(s, 8))

/* generic access and iterators over a stream of items/parts */
#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8(KDBUS_ITEM_HEADER_SIZE + (s))
#define KDBUS_ITEM_NEXT(part) \
	(typeof(part))(((u8 *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_ITEM_FOREACH(part, head, first)				\
	for (part = (head)->first;					\
	     (u8 *)(part) < (u8 *)(head) + (head)->size;		\
	     part = KDBUS_ITEM_NEXT(part))
#define KDBUS_ITEM_VALID(part, head)					\
	((part)->size > KDBUS_ITEM_HEADER_SIZE &&			\
	 (u8 *)(part) + (part)->size <= (u8 *)(head) + (head)->size)
#define KDBUS_ITEM_END(part, head)					\
	((u8 *)part == ((u8 *)(head) + KDBUS_ALIGN8((head)->size)))

/**
 * kdbus_size_get_user - read the size variable from user memory
 * @_s:			Size variable
 * @_b:			Buffer to read from
 * @_t:			Structure "size" is embedded in
 *
 * Returns: the result of copy_from_user()
 */
#define kdbus_size_get_user(_s, _b, _t)						\
({										\
	u64 __user *_sz = (void __user *)(_b) + offsetof(typeof(_t), size);	\
	copy_from_user(_s, _sz, sizeof(__u64));					\
})

/**
 * kdbus_offset_set_user - write the offset variable to user memory
 * @_s:			Offset variable
 * @_b:			Buffer to write to
 * @_t:			Structure "offset" is embedded in
 *
 * Returns: the result of copy_to_user()
 */
#define kdbus_offset_set_user(_s, _b, _t)					\
({										\
	u64 __user *_sz = (void __user *)(_b) + offsetof(typeof(_t), offset);	\
	copy_to_user(_sz, _s, sizeof(__u64));					\
})

/**
 * kdbus_validate_nul - check the validity of a sized string
 * @s:			String
 * @l:			Length of string
 *
 * Validate that a given string matches the given size, and the
 * string is \0 terminated.
 *
 * Returns: true if the given string is valid
 */
static inline bool kdbus_validate_nul(const char *s, size_t l)
{
	return l > 0 && memchr(s, '\0', l) == s + l - 1;
}

/**
 * kdbus_str_hash - calculate a hash
 * @str:		String
 *
 * Returns: hash value
 */
static inline unsigned int kdbus_str_hash(const char *str)
{
	return full_name_hash(str, strlen(str));
}
#endif
