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
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/init.h>

//#include <uapi/kdbus/kdbus.h>

#include "kdbus_internal.h"

void kdbus_release(struct device *dev)
{
	kfree(dev);
}


struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus)
{
	kref_get(&bus->kref);
	return bus;
}

static void __kdbus_bus_free(struct kref *kref)
{
	struct kdbus_bus *bus = container_of(kref, struct kdbus_bus, kref);

	kdbus_name_registry_unref(bus->name_registry);
	kdbus_bus_disconnect(bus);
	pr_info("clean up bus %s/%s\n",
		bus->ns->devpath, bus->name);

	kfree(bus->name);
	kfree(bus);
}

void kdbus_bus_unref(struct kdbus_bus *bus)
{
	kref_put(&bus->kref, __kdbus_bus_free);
}

struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id)
{
	struct kdbus_conn *conn;

	hash_for_each_possible(bus->conn_hash, conn, hentry, id)
		if (conn->id == id)
			return conn;

	return NULL;
}

void kdbus_bus_disconnect(struct kdbus_bus *bus)
{
	struct kdbus_ep *ep, *tmp;

	if (bus->disconnected)
		return;
	bus->disconnected = true;

	/* remove any endpoints attached to this bus */
	list_for_each_entry_safe(ep, tmp, &bus->ep_list, bus_entry) {
		kdbus_ep_disconnect(ep);
		kdbus_ep_unref(ep);
	}

	pr_info("closing bus %s/%s\n", bus->ns->devpath, bus->name);
}

int kdbus_bus_new(struct kdbus_ns *ns, const char *name, u64 bus_flags,
		  umode_t mode, uid_t uid, gid_t gid, struct kdbus_bus **bus)
{
	char prefix[16];
	struct kdbus_bus *b;
	int ret;

	/* enforce "$UID-" prefix */
	snprintf(prefix, sizeof(prefix), "%u-", uid);
	if (strncmp(name, prefix, strlen(prefix) != 0))
		return -EINVAL;

	b = kzalloc(sizeof(struct kdbus_bus), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	kref_init(&b->kref);
	b->ns = ns;
	b->bus_flags = bus_flags;
	/* connection 0 == kernel */
	b->conn_id_next = 1;
	mutex_init(&b->lock);
	hash_init(b->conn_hash);
	INIT_LIST_HEAD(&b->ep_list);
	b->name = kstrdup(name, GFP_KERNEL);
	if (!b->name) {
		ret = -ENOMEM;
		goto ret;
	}

	b->name_registry = kdbus_name_registry_new();
	if (!b->name_registry) {
		ret = -ENOMEM;
		goto ret;
	}

	ret = kdbus_ep_new(b, "bus", mode, uid, gid, &b->ep);
	if (ret < 0)
		goto ret;

	mutex_lock(&ns->lock);
	b->id = ns->bus_id_next++;
	mutex_unlock(&ns->lock);

	*bus = b;
	pr_info("created bus %llu '%s/%s'\n",
		(unsigned long long)b->id, ns->devpath, b->name);
	return 0;
ret:
	kdbus_bus_unref(b);
	return ret;
}
