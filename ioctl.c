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

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include "bus.h"
#include "domain.h"
#include "item.h"
#include "kdbus.h"
#include "limits.h"
#include "util.h"

struct kdbus_bus *kdbus_ioctl_bus_make(struct kdbus_domain *domain,
				       void __user *buf)
{
	struct kdbus_cmd_make *make;
	struct kdbus_bus *bus;
	int ret;

	make = kdbus_memdup_user(buf, sizeof(*make), KDBUS_MAKE_MAX_SIZE);
	if (IS_ERR(make))
		return ERR_CAST(make);

	ret = kdbus_negotiate_flags(make, buf, struct kdbus_cmd_make,
				    KDBUS_MAKE_ACCESS_GROUP |
				    KDBUS_MAKE_ACCESS_WORLD);
	if (ret < 0) {
		bus = ERR_PTR(ret);
		goto exit;
	}

	ret = kdbus_items_validate(make->items, KDBUS_ITEMS_SIZE(make, items));
	if (ret < 0) {
		bus = ERR_PTR(ret);
		goto exit;
	}

	bus = kdbus_bus_new(domain, make, current_fsuid(), current_fsgid());
	if (IS_ERR(bus))
		goto exit;

	ret = kdbus_bus_activate(bus);
	if (ret < 0) {
		kdbus_bus_unref(bus);
		bus = ERR_PTR(ret);
		goto exit;
	}

exit:
	kfree(make);
	return bus;
}
