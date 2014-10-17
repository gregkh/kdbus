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
#include <linux/uaccess.h>

#include "limits.h"
#include "util.h"

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
 * kdbus_negotiate_flags() - check flags provided by user, and write the
 *			     valid mask back
 * @flags:	The flags mask provided by userspace
 * @buf:	The buffer provided by userspace
 * @offset:	Offset of the flags field inside the user-provided struct
 * @valid:	Mask of valid bits
 *
 * This function will check whether the flags provided by userspace are within
 * the combination of allowed bits to the kernel, with the KDBUS_FLAGS_KERNEL
 * bit set in the return buffer.
 *
 * Return: 0 on success, -EFAULT if copy_to_user() failed, or -EINVAL if
 * userspace submitted invalid bits in its mask.
 */
int kdbus_negotiate_flags(u64 flags, void __user *buf, off_t offset, u64 valid)
{
	u64 val = valid | KDBUS_FLAG_KERNEL;

	/*
	 * KDBUS_FLAG_KERNEL is reserved. Make sure it is never considered
	 * valid by any user of this function.
	 */
	BUG_ON(valid & KDBUS_FLAG_KERNEL);

	if (copy_to_user(((u8 __user *) buf) + offset, &val, sizeof(val)))
		return -EFAULT;

	if (flags & ~valid)
		return -EINVAL;

	return 0;
}
