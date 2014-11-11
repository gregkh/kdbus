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
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>

#include "util.h"
#include "domain.h"
#include "handle.h"
#include "node.h"

/* kdbus initial domain */
static struct kdbus_domain *kdbus_domain_init;

static int __init kdbus_init(void)
{
	int ret;

	ret = subsys_virtual_register(&kdbus_subsys, NULL);
	if (ret < 0)
		return ret;

	ret = kdbus_cdev_init();
	if (ret < 0)
		goto exit_subsys;

	kdbus_init_nodes();

	/*
	 * Create the initial domain; it is world-accessible and
	 * provides the /dev/kdbus/control device node.
	 */
	kdbus_domain_init = kdbus_domain_new(NULL, NULL, 0666);
	if (IS_ERR(kdbus_domain_init)) {
		ret = PTR_ERR(kdbus_domain_init);
		pr_err("failed to initialize, error=%i\n", ret);
		goto exit_node;
	}

	ret = kdbus_domain_activate(kdbus_domain_init);
	if (ret < 0) {
		pr_err("failed to initialize, error=%i\n", ret);
		goto exit_domain;
	}

	pr_info("initialized\n");
	return 0;

exit_domain:
	kdbus_domain_unref(kdbus_domain_init);
exit_node:
	kdbus_exit_nodes();
	kdbus_cdev_exit();
exit_subsys:
	bus_unregister(&kdbus_subsys);
	return ret;
}

static void __exit kdbus_exit(void)
{
	kdbus_domain_deactivate(kdbus_domain_init);
	kdbus_domain_unref(kdbus_domain_init);
	kdbus_exit_nodes();
	kdbus_cdev_exit();
	bus_unregister(&kdbus_subsys);
}

module_init(kdbus_init);
module_exit(kdbus_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("D-Bus, powerful, easy to use interprocess communication");
