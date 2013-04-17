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

#define KDBUS_CHAR_MAJOR	222		/* FIXME: move to uapi/linux/major.h */

#define KDBUS_IS_ALIGNED8(s) (((u64)(s) & 7) == 0)
#define KDBUS_ALIGN8(s) ALIGN((s), 8)

#define KDBUS_ITEM_HEADER_SIZE offsetof(union kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)
#define KDBUS_ITEM_NEXT(item) \
	(typeof(item))(((u8 *)item) + KDBUS_ALIGN8((item)->size))
#define KDBUS_ITEM_FOREACH(item, head)						\
	for (item = (head)->items;						\
	     (u8 *)(item) + KDBUS_ITEM_HEADER_SIZE <= (u8 *)(head) + (head)->size && \
	     (u8 *)(item) + (item)->size <= (u8 *)(head) + (head)->size; \
	     item = KDBUS_ITEM_NEXT(item))

/* copy the uint64_t "size" value from the userspace-supplied  structure */
//FIXME: intentionally broken to make ARM's missing get_user() work
#define kdbus_size_get_user(_s, _b, _t) \
({ \
	u64 __user *_sz = _b + offsetof(typeof(_t), size); \
	get_user(_s, _sz); \
})

#define kdbus_size_set_user(_s, _b, _t) \
({ \
	u64 __user *_sz = _b + offsetof(typeof(_t), size); \
	put_user(_s, _sz); \
})

union kdbus_item {
	struct {
		__u64 size;
		__u64 type;
		u8 data[0];
	};
	struct kdbus_msg_item msg_item;
	struct kdbus_cmd_match_item cmd_match_item;
};

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
