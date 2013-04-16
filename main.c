/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <uapi/linux/major.h>

#include "internal.h"
#include "ns.h"

/* kdbus sysfs subsystem */
struct bus_type kdbus_subsys = {
	.name = "kdbus",
};

/* kdbus initial namespace */
struct kdbus_ns *kdbus_ns_init;

/* map of majors to namespaces */
DEFINE_IDR(kdbus_ns_major_idr);

static int __init kdbus_init(void)
{
	int ret;

	ret = bus_register(&kdbus_subsys);
	if (ret < 0)
		return ret;

	ret = kdbus_ns_new(NULL, NULL, 0666, &kdbus_ns_init);
	if (ret < 0) {
		bus_unregister(&kdbus_subsys);
		pr_err("failed to initialize ret=%i\n", ret);
		return ret;
	}

	pr_info("initialized\n");
	return 0;
}

static void __exit kdbus_exit(void)
{
	kdbus_ns_unref(kdbus_ns_init);
	bus_unregister(&kdbus_subsys);
	pr_info("unloaded\n");
}

module_init(kdbus_init);
module_exit(kdbus_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kdbus interprocess communication");
MODULE_ALIAS_CHARDEV(KDBUS_CHAR_MAJOR, 0);
MODULE_ALIAS("devname:kdbus/control");
