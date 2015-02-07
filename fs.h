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

#ifndef __KDBUSFS_H
#define __KDBUSFS_H

#include <linux/kernel.h>

struct kdbus_node;

int kdbus_fs_init(void);
void kdbus_fs_exit(void);
void kdbus_fs_flush(struct kdbus_node *node);

#define kdbus_node_from_inode(_inode) \
	((struct kdbus_node *)(_inode)->i_private)

#endif
