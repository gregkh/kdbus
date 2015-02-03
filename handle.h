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

#ifndef __KDBUS_HANDLE_H
#define __KDBUS_HANDLE_H

#include <linux/fs.h>
#include "kdbus.h"

extern const struct file_operations kdbus_handle_ops;

struct kdbus_arg {
	u64 type;
	struct kdbus_item *item;
	bool multiple : 1;
	bool mandatory : 1;
};

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
