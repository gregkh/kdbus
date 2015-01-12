/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 * Copyright (C) 2014 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/user_namespace.h>

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
		if (i > 0 && i + 1 < len && (name[i] == '-' || name[i] == '.'))
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

	if (copy_to_user(((u8 __user *)buf) + offset_out, &val, sizeof(val)))
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

	if (!files || count == 0)
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
	void *ptr;
	u64 size;
	int ret;

	ret = kdbus_copy_from_user(&size, user_ptr, sizeof(size));
	if (ret < 0)
		return ERR_PTR(ret);

	if (size < sz_min)
		return ERR_PTR(-EINVAL);

	if (size > sz_max)
		return ERR_PTR(-EMSGSIZE);

	ptr = memdup_user(user_ptr, size);
	if (IS_ERR(ptr))
		return ptr;

	if (*(u64 *)ptr != size) {
		kfree(ptr);
		return ERR_PTR(-EINVAL);
	}

	return ptr;
}

/**
 * kdbus_verify_uid_prefix() - verify UID prefix of a user-supplied name
 * @name:	user-supplied name to verify
 * @user_ns:	user-namespace to act in
 * @kuid:	Kernel internal uid of user
 *
 * This verifies that the user-supplied name @name has their UID as prefix. This
 * is the default name-spacing policy we enforce on user-supplied names for
 * public kdbus entities like buses and endpoints.
 *
 * The user must supply names prefixed with "<UID>-", whereas the UID is
 * interpreted in the user-namespace of the domain. If the user fails to supply
 * such a prefixed name, we reject it.
 *
 * Return: 0 on success, negative error code on failure
 */
int kdbus_verify_uid_prefix(const char *name, struct user_namespace *user_ns,
			    kuid_t kuid)
{
	uid_t uid;
	char prefix[16];

	/*
	 * The kuid must have a mapping into the userns of the domain
	 * otherwise do not allow creation of buses nor endpoints.
	 */
	uid = from_kuid(user_ns, kuid);
	if (uid == (uid_t) -1)
		return -EINVAL;

	snprintf(prefix, sizeof(prefix), "%u-", uid);
	if (strncmp(name, prefix, strlen(prefix)) != 0)
		return -EINVAL;

	return 0;
}

/**
 * kdbus_from_kuid_keep() - Create a uid from kuid/user-ns pair
 * @uid:		Kernel uid to map into @user_ns
 *
 * This is equivalent to from_kuid_munged(), but maps INVALID_UID to itself.
 *
 * Return: UID @uid mapped into @user_ns, or INVALID_UID if @uid==INVALID_UID.
 */
u32 kdbus_from_kuid_keep(kuid_t uid)
{
	return uid_valid(uid) ?
		from_kuid_munged(current_user_ns(), uid) : ((uid_t)-1);
}

/**
 * kdbus_from_kgid_keep() - Create a gid from kgid/user-ns pair
 * @gid:		Kernel gid to map into @user_ns
 *
 * This is equivalent to from_kgid_munged(), but maps INVALID_GID to itself.
 *
 * Return: GID @gid mapped into @user_ns, or INVALID_GID if @gid==INVALID_GID.
 */
u32 kdbus_from_kgid_keep(kgid_t gid)
{
	return gid_valid(gid) ?
		from_kgid_munged(current_user_ns(), gid) : ((gid_t)-1);
}

/**
 * kdbus_sanitize_attach_flags() - Sanitize attach flags from user-space
 * @flags:		Attach flags provided by userspace
 * @attach_flags:	A pointer where to store the valid attach flags
 *
 * Convert attach-flags provided by user-space into a valid mask. If the mask
 * is invalid, an error is returned. The sanitized attach flags are stored in
 * the output parameter.
 *
 * Return: 0 on success, negative error on failure.
 */
int kdbus_sanitize_attach_flags(u64 flags, u64 *attach_flags)
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

/**
 * kdbus_kvec_set - helper utility to assemble kvec arrays
 * @kvec:	kvec entry to use
 * @src:	Source address to set in @kvec
 * @len:	Number of bytes in @src
 * @total_len:	Pointer to total length variable
 *
 * Set @src and @len in @kvec, and increase @total_len by @len.
 */
void kdbus_kvec_set(struct kvec *kvec, void *src, size_t len, u64 *total_len)
{
	kvec->iov_base = src;
	kvec->iov_len = len;
	*total_len += len;
}

static const char * const zeros = "\0\0\0\0\0\0\0";

/**
 * kdbus_kvec_pad - conditionally write a padding kvec
 * @kvec:	kvec entry to use
 * @len:	Total length used for kvec array
 *
 * Check if the current total byte length of the array in @len is aligned to
 * 8 bytes. If it isn't, fill @kvec with padding information and increase @len
 * by the number of bytes stored in @kvec.
 *
 * Return: the number of added padding bytes.
 */
size_t kdbus_kvec_pad(struct kvec *kvec, u64 *len)
{
	size_t pad = KDBUS_ALIGN8(*len) - *len;

	if (!pad)
		return 0;

	kvec->iov_base = (void *)zeros;
	kvec->iov_len = pad;

	*len += pad;

	return pad;
}
