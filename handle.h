/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_HANDLE_H
#define __KDBUS_HANDLE_H

#include <linux/fs.h>
#include "kdbus.h"

extern const struct file_operations kdbus_handle_ops;

/**
 * kdbus_arg - information and state of a single ioctl command item
 * @type:		item type
 * @item:		set by the parser to the first found item of this type
 * @multiple:		whether multiple items of this type are allowed
 * @mandatory:		whether at least one item of this type is required
 *
 * This structure describes a single item in an ioctl command payload. The
 * caller has to pre-fill the type and flags, the parser will then use this
 * information to verify the ioctl payload. @item is set by the parser to point
 * to the first occurrence of the item.
 */
struct kdbus_arg {
	u64 type;
	struct kdbus_item *item;
	bool multiple : 1;
	bool mandatory : 1;
};

/**
 * kdbus_args - information and state of ioctl command parser
 * @allowed_flags:	set of flags this command supports
 * @argc:		number of items in @argv
 * @argv:		array of items this command supports
 * @user:		set by parser to user-space location of current command
 * @cmd:		set by parser to kernel copy of command payload
 * @items:		points to item array in @cmd
 * @items_size:		size of @items in bytes
 *
 * This structure is used to parse ioctl command payloads on each invokation.
 * The ioctl handler has to pre-fill the flags and allowed items before passing
 * the object to kdbus_args_parse(). The parser will copy the command payload
 * into kernel-space and verify the correctness of the data.
 */
struct kdbus_args {
	u64 allowed_flags;
	size_t argc;
	struct kdbus_arg *argv;

	struct kdbus_cmd __user *user;
	struct kdbus_cmd *cmd;

	struct kdbus_item *items;
	size_t items_size;
};

int __kdbus_args_parse(struct kdbus_args *args, void __user *argp,
		       size_t type_size, size_t items_offset, void **out);
int kdbus_args_clear(struct kdbus_args *args, int ret);

#define kdbus_args_parse(_args, _argp, _v)                              \
	({                                                              \
		BUILD_BUG_ON(offsetof(typeof(**(_v)), size) !=          \
			     offsetof(struct kdbus_cmd, size));         \
		BUILD_BUG_ON(offsetof(typeof(**(_v)), flags) !=         \
			     offsetof(struct kdbus_cmd, flags));        \
		BUILD_BUG_ON(offsetof(typeof(**(_v)), return_flags) !=  \
			     offsetof(struct kdbus_cmd, return_flags)); \
		__kdbus_args_parse((_args), (_argp), sizeof(**(_v)),    \
				   offsetof(typeof(**(_v)), items),     \
				   (void**)(_v));                       \
	})

#endif
