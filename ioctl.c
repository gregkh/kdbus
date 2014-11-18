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
#include <linux/uaccess.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "ioctl.h"
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

struct kdbus_ep *kdbus_ioctl_endpoint_make(struct kdbus_bus *bus,
					   void __user *buf)
{
	struct kdbus_ep *res, *ep = NULL;
	struct kdbus_domain_user *user;
	struct kdbus_cmd_make *make;
	unsigned int access;
	const char *name;
	int ret;

	make = kdbus_memdup_user(buf, sizeof(*make), KDBUS_MAKE_MAX_SIZE);
	if (IS_ERR(make))
		return ERR_CAST(make);

	ret = kdbus_negotiate_flags(make, buf, struct kdbus_cmd_make,
				    KDBUS_MAKE_ACCESS_GROUP |
				    KDBUS_MAKE_ACCESS_WORLD);
	if (ret < 0) {
		res = ERR_PTR(ret);
		goto exit;
	}

	ret = kdbus_items_validate(make->items, KDBUS_ITEMS_SIZE(make, items));
	if (ret < 0) {
		res = ERR_PTR(ret);
		goto exit;
	}

	name = kdbus_items_get_str(make->items, KDBUS_ITEMS_SIZE(make, items),
				   KDBUS_ITEM_MAKE_NAME);
	if (IS_ERR(name)) {
		res = ERR_CAST(name);
		goto exit;
	}

	access = make->flags & (KDBUS_MAKE_ACCESS_WORLD |
				KDBUS_MAKE_ACCESS_GROUP);

	ep = kdbus_ep_new(bus, name, access, current_fsuid(), current_fsgid(),
			  true);
	if (IS_ERR(ep)) {
		res = ep;
		goto exit;
	}

	/*
	 * Get an anonymous user to account messages against; custom
	 * endpoint users do not share the budget with the ordinary
	 * users created for a UID.
	 */
	user = kdbus_domain_get_user(bus->domain, INVALID_UID);
	if (IS_ERR(user)) {
		res = ERR_CAST(user);
		goto exit_ep_unref;
	}
	ep->user = user;

	ret = kdbus_ep_activate(ep);
	if (ret < 0) {
		res = ERR_PTR(ret);
		goto exit_ep_unref;
	}

	ret = kdbus_ep_policy_set(ep, make->items,
				  KDBUS_ITEMS_SIZE(make, items));
	if (ret < 0) {
		res = ERR_PTR(ret);
		goto exit_ep_live;
	}

	res = ep;
	goto exit;

exit_ep_live:
	kdbus_ep_deactivate(ep);
exit_ep_unref:
	kdbus_ep_unref(ep);
exit:
	kfree(make);
	return res;
}

struct kdbus_conn *kdbus_ioctl_hello(struct kdbus_ep *ep,
				     struct kdbus_meta *meta,
				     bool privileged,
				     void __user *buf)
{
	struct kdbus_conn *res, *conn = NULL;
	struct kdbus_cmd_hello *hello;
	int ret;

	hello = kdbus_memdup_user(buf, sizeof(*hello), KDBUS_HELLO_MAX_SIZE);
	if (IS_ERR(hello))
		return ERR_CAST(hello);

	ret = kdbus_negotiate_flags(hello, buf, typeof(*hello),
				    KDBUS_HELLO_ACCEPT_FD |
				    KDBUS_HELLO_ACTIVATOR |
				    KDBUS_HELLO_POLICY_HOLDER |
				    KDBUS_HELLO_MONITOR);
	if (ret < 0) {
		res = ERR_PTR(ret);
		goto exit;
	}

	ret = kdbus_items_validate(hello->items,
				   KDBUS_ITEMS_SIZE(hello, items));
	if (ret < 0) {
		res = ERR_PTR(ret);
		goto exit;
	}

	if (!hello->pool_size || !IS_ALIGNED(hello->pool_size, PAGE_SIZE)) {
		res = ERR_PTR(-EFAULT);
		goto exit;
	}

	conn = kdbus_conn_new(ep, hello, meta, privileged);
	if (IS_ERR(conn)) {
		res = conn;
		goto exit;
	}

	if (copy_to_user(buf, hello, sizeof(*hello))) {
		res = ERR_PTR(-EFAULT);
		goto exit_conn_live;
	}

	res = conn;
	goto exit;

exit_conn_live:
	kdbus_conn_disconnect(conn, false);
	kdbus_conn_unref(conn);
exit:
	kfree(hello);
	return res;
}
