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

#ifndef __KDBUS_INTERNAL_H
#define __KDBUS_INTERNAL_H

//#include <uapi/kdbus/kdbus.h>
#include "kdbus.h"

#define KDBUS_MSG_MAX_SIZE		SZ_8K		/* maximum size of message header and items */
#define KDBUS_MSG_MAX_ITEMS		128		/* maximum number of message items */
#define KDBUS_MSG_MAX_FDS		256		/* maximum number of passed file descriptors */
#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE	SZ_2M		/* maximum message payload size */

#define KDBUS_NAME_MAX_LEN		255		/* maximum length of well-known bus name */

#define KDBUS_MAKE_MAX_LEN		63		/* maximum length of bus, ns, ep name */
#define KDBUS_MAKE_MAX_SIZE		SZ_32K		/* maximum size of make data */

#define KDBUS_HELLO_MAX_SIZE		SZ_32K		/* maximum size of hello data */
#define KDBUS_MATCH_MAX_SIZE		SZ_32K		/* maximum size of match data */
#define KDBUS_POLICY_MAX_SIZE		SZ_32K		/* maximum size of policy data */

#define KDBUS_CONN_MAX_MSGS		64		/* maximum number of queued messages on the bus */
#define KDBUS_CONN_MAX_ALLOCATED_BYTES	SZ_64K		/* maximum number of allocated bytes on the bus */

#define KDBUS_CHAR_MAJOR		222		/* FIXME: move to uapi/linux/major.h */

#define KDBUS_VEC_PTR(vec) ((void *)(uintptr_t)(vec)->address)
#define KDBUS_VEC_ADDR(ptr) ((u64)(ptr))

#define KDBUS_ALIGN8(s) ALIGN((s), 8)
#define KDBUS_IS_ALIGNED8(s) (IS_ALIGNED(s, 8))
#define KDBUS_IS_ALIGNED_PAGE(s) (IS_ALIGNED(s, PAGE_SIZE))

#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)
#define KDBUS_ITEM_NEXT(item) \
	(struct kdbus_item *)((u8 *)item + KDBUS_ALIGN8((item)->size))
#define KDBUS_ITEM_FOREACH(item, head)						\
	for (item = (head)->items;						\
	     (u8 *)(item) < (u8 *)(head) + (head)->size;			\
	     item = KDBUS_ITEM_NEXT(item))
/* same iterator with more consistency checks, to be used with incoming data */
#define KDBUS_ITEM_FOREACH_VALIDATE(item, head)					\
	for (item = (head)->items;						\
	     (u8 *)(item) + KDBUS_ITEM_HEADER_SIZE <= (u8 *)(head) + (head)->size && \
	     (u8 *)(item) + (item)->size <= (u8 *)(head) + (head)->size; \
	     item = KDBUS_ITEM_NEXT(item))

#define KDBUS_MSG_HEADER_SIZE offsetof(struct kdbus_msg, items)

/* some architectures miss get_user_8(); copy only the lower 32bit */
#ifdef CONFIG_64BIT
#define kdbus_size_get_user(_s, _b, _t) \
({ \
	u64 __user *_sz = (void __user *)(_b) + offsetof(typeof(_t), size); \
	get_user(_s, _sz); \
})
#else
	#ifdef __LITTLE_ENDIAN__
	#define kdbus_size_get_user(_s, _b, _t) \
	({ \
		u32 __user *_sz = (void __user *)(_b) + offsetof(typeof(_t), size); \
		get_user(_s, _sz); \
	})
	#else
	#define kdbus_size_get_user(_s, _b, _t) \
	({ \
		u32 __user *_sz = (void __user *)(_b) + sizeof(u32) + offsetof(typeof(_t), size); \
		get_user(_s, _sz); \
	})
	#endif
#endif

#define kdbus_size_set_user(_s, _b, _t) \
({ \
	u64 __user *_sz = _b + offsetof(typeof(_t), size); \
	put_user(_s, _sz); \
})

static inline bool kdbus_validate_nul(const char *s, size_t l)
{
	return l > 0 && memchr(s, '\0', l) == s + l - 1;
}

static inline unsigned int kdbus_str_hash(const char *str)
{
	return full_name_hash(str, strlen(str));
}

extern const struct file_operations kdbus_device_ops;
extern struct bus_type kdbus_subsys;
void kdbus_dev_release(struct device *dev);
extern struct mutex kdbus_subsys_lock;
extern struct idr kdbus_ns_major_idr;
extern struct kdbus_ns *kdbus_ns_init;
#endif
