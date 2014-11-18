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
#include <linux/file.h>
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
 * kdbus_check_and_write_flags() - check flags provided by user, and write the
 *				   valid mask back
 * @flags:	The flags mask provided by userspace
 * @buf:	The buffer provided by userspace
 * @offset_out:	Offset of the kernel_flags field inside the user-provided struct
 * @valid:	Mask of valid bits
 *
 * This function will check whether the flags provided by userspace are within
 * the combination of allowed bits to the kernel, with the KDBUS_FLAGS_KERNEL
 * bit set in the return buffer.
 *
 * Return: 0 on success, -EFAULT if copy_to_user() failed, or -EINVAL if
 * userspace submitted invalid bits in its mask.
 */
int kdbus_check_and_write_flags(u64 flags, void __user *buf,
			  off_t offset_out, u64 valid)
{
	u64 val = valid | KDBUS_FLAG_KERNEL;

	/*
	 * KDBUS_FLAG_KERNEL is reserved and will never be considered
	 * valid by any user of this function.
	 */
	WARN_ON_ONCE(valid & KDBUS_FLAG_KERNEL);

	if (copy_to_user(((u8 __user *) buf) + offset_out, &val, sizeof(val)))
		return -EFAULT;

	if (flags & ~valid)
		return -EINVAL;

	return 0;
}

/**
 * kdbus_fput_files() - fput() an array of struct files
 * @files:	The array of files to put, may be NULL
 * @count:	The number of elements in @files
 *
 * Call fput() on all non-NULL elements in @files, and set the entries to
 * NULL afterwards.
 */
void kdbus_fput_files(struct file **files, unsigned int count)
{
	int i;

	if (!files)
		return;

	for (i = count - 1; i >= 0; i--)
		if (files[i]) {
			fput(files[i]);
			files[i] = NULL;
		}
}

/**
 * kdbus_copy_from_user() - copy aligned data from user-space
 * @dest:	target buffer in kernel memory
 * @user_ptr:	user-provided source buffer
 * @size:	memory size to copy from user
 *
 * This copies @size bytes from @user_ptr into the kernel, just like
 * copy_from_user() does. But we enforce an 8-byte alignment and reject any
 * unaligned user-space pointers.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_copy_from_user(void *dest, void __user *user_ptr, size_t size)
{
	if (!KDBUS_IS_ALIGNED8((uintptr_t)user_ptr))
		return -EFAULT;

	if (copy_from_user(dest, user_ptr, size))
		return -EFAULT;

	return 0;
}

/**
 * kdbus_memdup_user() - copy dynamically sized object from user-space
 * @user_ptr:	user-provided source buffer
 * @sz_min:	minimum object size
 * @sz_max:	maximum object size
 *
 * This copies a dynamically sized object from user-space into kernel-space. We
 * require the object to have a 64bit size field at offset 0. We read it out
 * first, allocate a suitably sized buffer and then copy all data.
 *
 * The @sz_min and @sz_max parameters define possible min and max object sizes
 * so user-space cannot trigger un-bound kernel-space allocations.
 *
 * The same alignment-restrictions as described in kdbus_copy_from_user() apply.
 *
 * Return: pointer to dynamically allocated copy, or ERR_PTR() on failure.
 */
void *kdbus_memdup_user(void __user *user_ptr, size_t sz_min, size_t sz_max)
{
	u64 size;
	int ret;

	ret = kdbus_copy_from_user(&size, user_ptr, sizeof(size));
	if (ret < 0)
		return ERR_PTR(ret);

	if (size < sz_min)
		return ERR_PTR(-EINVAL);

	if (size > sz_max)
		return ERR_PTR(-EMSGSIZE);

	return memdup_user(user_ptr, size);
}
