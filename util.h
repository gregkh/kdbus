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

#ifndef __KDBUS_UTIL_H
#define __KDBUS_UTIL_H

#include <linux/dcache.h>
#include <linux/ioctl.h>
#include <linux/uidgid.h>

#include "kdbus.h"

/* all exported addresses are 64 bit */
#define KDBUS_PTR(addr) ((void __user *)(uintptr_t)(addr))

/* all exported sizes are 64 bit and data aligned to 64 bit */
#define KDBUS_ALIGN8(s) ALIGN((s), 8)
#define KDBUS_IS_ALIGNED8(s) (IS_ALIGNED(s, 8))

/**
 * kdbus_size_get_user - read the size variable from user memory
 * @_s:		Size variable
 * @_b:		Buffer to read from
 * @_t:		Structure, "size" is a member of
 *
 * Return: the result of copy_from_user()
 */
#define kdbus_size_get_user(_s, _b, _t)					\
({									\
	u64 __user *_sz =						\
		(void __user *)((u8 __user *)(_b) + offsetof(_t, size));\
	copy_from_user(_s, _sz, sizeof(__u64));				\
})

/**
 * kdbus_member_set_user - write a structure member to user memory
 * @_s:		Variable to copy from
 * @_b:		Buffer to write to
 * @_t:		Structure type
 * @_m:		Member name in the passed structure
 *
 * Return: the result of copy_to_user()
 */
#define kdbus_member_set_user(_s, _b, _t, _m)				\
({									\
	u64 __user *_sz =						\
		(void __user *)((u8 __user *)(_b) + offsetof(_t, _m));	\
	copy_to_user(_sz, _s, sizeof(((_t *)0)->_m));			\
})

/**
 * kdbus_strhash - calculate a hash
 * @str:	String
 *
 * Return: hash value
 */
static inline unsigned int kdbus_strhash(const char *str)
{
	unsigned long hash = init_name_hash();

	while (*str)
		hash = partial_name_hash(*str++, hash);

	return end_name_hash(hash);
}

/**
 * kdbus_strnhash - calculate a hash
 * @str:	String
 * @len:	Length of @str
 *
 * Return: hash value
 */
static inline unsigned int kdbus_strnhash(const char *str, size_t len)
{
	unsigned long hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(*str++, hash);

	return end_name_hash(hash);
}

/**
 * kdbus_str_valid - verify a string
 * @str:	String to verify
 * @size:	Size of buffer of string (including 0-byte)
 *
 * This verifies the string at position @str with size @size is properly
 * zero-terminated and does not contain a 0-byte but at the end.
 *
 * Return: true if string is valid, false if not.
 */
static inline bool kdbus_str_valid(const char *str, size_t size)
{
	return size > 0 && memchr(str, '\0', size) == str + size - 1;
}

int kdbus_verify_uid_prefix(const char *name, struct user_namespace *user_ns,
			    kuid_t kuid);
int kdbus_sanitize_attach_flags(u64 flags, u64 *attach_flags);

int kdbus_copy_from_user(void *dest, void __user *user_ptr, size_t size);
void *kdbus_memdup_user(void __user *user_ptr, size_t sz_min, size_t sz_max);

struct kvec;

void kdbus_kvec_set(struct kvec *kvec, void *src, size_t len, u64 *total_len);
size_t kdbus_kvec_pad(struct kvec *kvec, u64 *len);

#endif
