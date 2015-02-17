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

#define pr_fmt(fmt)    KBUILD_MODNAME ": " fmt
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "util.h"
#include "fs.h"
#include "handle.h"
#include "metadata.h"
#include "node.h"

/*
 * This is a simplified outline of the internal kdbus object relations, for
 * those interested in the inner life of the driver implementation.
 *
 * From a mount point's (domain's) perspective:
 *
 * struct kdbus_domain
 *   |» struct kdbus_user *user (many, owned)
 *   '» struct kdbus_node node (embedded)
 *       |» struct kdbus_node children (many, referenced)
 *       |» struct kdbus_node *parent (pinned)
 *       '» struct kdbus_bus (many, pinned)
 *           |» struct kdbus_node node (embedded)
 *           '» struct kdbus_ep (many, pinned)
 *               |» struct kdbus_node node (embedded)
 *               |» struct kdbus_bus *bus (pinned)
 *               |» struct kdbus_conn conn_list (many, pinned)
 *               |   |» struct kdbus_ep *ep (pinned)
 *               |   |» struct kdbus_name_entry *activator_of (owned)
 *               |   |» struct kdbus_match_db *match_db (owned)
 *               |   |» struct kdbus_meta *meta (owned)
 *               |   |» struct kdbus_match_db *match_db (owned)
 *               |   |    '» struct kdbus_match_entry (many, owned)
 *               |   |
 *               |   |» struct kdbus_pool *pool (owned)
 *               |   |    '» struct kdbus_pool_slice *slices (many, owned)
 *               |   |       '» struct kdbus_pool *pool (pinned)
 *               |   |
 *               |   |» struct kdbus_user *user (pinned)
 *               |   `» struct kdbus_queue_entry entries (many, embedded)
 *               |        |» struct kdbus_pool_slice *slice (pinned)
 *               |        |» struct kdbus_conn_reply *reply (owned)
 *               |        '» struct kdbus_user *user (pinned)
 *               |
 *               '» struct kdbus_user *user (pinned)
 *                   '» struct kdbus_policy_db policy_db (embedded)
 *                        |» struct kdbus_policy_db_entry (many, owned)
 *                        |   |» struct kdbus_conn (pinned)
 *                        |   '» struct kdbus_ep (pinned)
 *                        |
 *                        '» struct kdbus_policy_db_cache_entry (many, owned)
 *                            '» struct kdbus_conn (pinned)
 *
 * For the life-time of a file descriptor derived from calling open() on a file
 * inside the mount point:
 *
 * struct kdbus_handle
 *  |» struct kdbus_meta *meta (owned)
 *  |» struct kdbus_ep *ep (pinned)
 *  |» struct kdbus_conn *conn (owned)
 *  '» struct kdbus_ep *ep (owned)
 */

/* kdbus mount-point /sys/fs/kdbus */
static struct kobject *kdbus_dir;

/* global module option to apply a mask to exported metadata */
unsigned long long kdbus_meta_attach_mask = KDBUS_ATTACH_TIMESTAMP |
					    KDBUS_ATTACH_CREDS |
					    KDBUS_ATTACH_PIDS |
					    KDBUS_ATTACH_AUXGROUPS |
					    KDBUS_ATTACH_NAMES |
					    KDBUS_ATTACH_SECLABEL |
					    KDBUS_ATTACH_CONN_DESCRIPTION;
MODULE_PARM_DESC(attach_flags_mask, "Attach-flags mask for exported metadata");
module_param_named(attach_flags_mask, kdbus_meta_attach_mask, ullong, 0644);

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
