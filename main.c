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

#define pr_fmt(fmt)    KBUILD_MODNAME ": " fmt
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "util.h"
#include "fs.h"
#include "handle.h"
#include "node.h"

/* kdbus mount-point /sys/fs/kdbus */
static struct kobject *kdbus_dir;

/* global module option to apply a mask to exported metadata */
unsigned int kdbus_meta_attach_mask = KDBUS_ATTACH_TIMESTAMP |
				      KDBUS_ATTACH_CREDS |
				      KDBUS_ATTACH_PIDS |
				      KDBUS_ATTACH_AUXGROUPS |
				      KDBUS_ATTACH_NAMES |
				      KDBUS_ATTACH_SECLABEL |
				      KDBUS_ATTACH_CONN_DESCRIPTION;
MODULE_PARM_DESC(attach_flags_mask, "Attach-flags mask for exported metadata");
module_param_named(attach_flags_mask, kdbus_meta_attach_mask, uint, 0644);

static int __init kdbus_init(void)
{
	int ret;

	kdbus_dir = kobject_create_and_add(KBUILD_MODNAME, fs_kobj);
	if (!kdbus_dir)
		return -ENOMEM;

	ret = kdbus_fs_init();
	if (ret < 0) {
		pr_err("cannot register filesystem: %d\n", ret);
		goto exit_dir;
	}

	pr_info("initialized\n");
	return 0;

exit_dir:
	kobject_put(kdbus_dir);
	return ret;
}

static void __exit kdbus_exit(void)
{
	kdbus_fs_exit();
	kobject_put(kdbus_dir);
}

module_init(kdbus_init);
module_exit(kdbus_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("D-Bus, powerful, easy to use interprocess communication");
MODULE_ALIAS_FS(KBUILD_MODNAME "fs");
