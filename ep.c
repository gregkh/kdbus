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
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/hashtable.h>

#include "ep.h"
#include "bus.h"
#include "policy.h"
#include "ns.h"

/* endpoints are by default owned by the bus owner */
static char *kdbus_devnode_ep(struct device *dev, umode_t *mode
#ifdef DRIVER_CORE_DEVICE_TYPE_DEVNODE_UID
		, kuid_t *uid, kgid_t *gid)
#else
		)
#endif
{
	struct kdbus_ep *ep = dev_get_drvdata(dev);

	if (mode)
		*mode = ep->mode;
#ifdef DRIVER_CORE_DEVICE_TYPE_DEVNODE_UID
	if (uid)
		*uid = ep->uid;
	if (gid)
		*gid = ep->gid;
#endif
	return NULL;
}

static struct device_type kdbus_devtype_ep = {
	.name		= "ep",
	.release	= kdbus_dev_release,
	.devnode	= kdbus_devnode_ep,
};

struct kdbus_ep *kdbus_ep_ref(struct kdbus_ep *ep)
{
	kref_get(&ep->kref);
	return ep;
}

void kdbus_ep_disconnect(struct kdbus_ep *ep)
{
	if (ep->disconnected)
		return;
	ep->disconnected = true;

	if (ep->dev) {
		device_unregister(ep->dev);
		ep->dev = NULL;
	}
	if (ep->minor > 0) {
		idr_remove(&ep->bus->ns->idr, ep->minor);
		ep->minor = 0;
	}
	pr_info("closing endpoint %s/%s/%s\n",
		ep->bus->ns->devpath, ep->bus->name, ep->name);
}

static void __kdbus_ep_free(struct kref *kref)
{
	struct kdbus_ep *ep = container_of(kref, struct kdbus_ep, kref);

	mutex_lock(&ep->bus->lock);
	kdbus_ep_disconnect(ep);
	pr_info("clean up endpoint %s/%s/%s\n",
		ep->bus->ns->devpath, ep->bus->name, ep->name);
	mutex_unlock(&ep->bus->lock);

	kdbus_bus_unref(ep->bus);
	if (ep->policy_db)
		kdbus_policy_db_unref(ep->policy_db);

	kfree(ep->name);
	kfree(ep);
}

void kdbus_ep_unref(struct kdbus_ep *ep)
{
	kref_put(&ep->kref, __kdbus_ep_free);
}

static struct kdbus_ep *kdbus_ep_find(struct kdbus_bus *bus, const char *name)
{
	struct kdbus_ep *ep = NULL;
	struct kdbus_ep *e;

	mutex_lock(&bus->lock);
	list_for_each_entry(e, &bus->ep_list, bus_entry) {
		if (strcmp(ep->name, name) != 0)
			continue;

		ep = kdbus_ep_ref(e);
	}
	mutex_unlock(&bus->lock);

	return ep;
}

int kdbus_ep_new(struct kdbus_bus *bus, const char *name, umode_t mode,
		 kuid_t uid, kgid_t gid, bool policy_open)
{
	struct kdbus_ep *e;
	int ret;
	int i;

	e = kdbus_ep_find(bus, name);
	if (e) {
		kdbus_ep_unref(e);
		return -EEXIST;
	}

	e = kzalloc(sizeof(struct kdbus_ep), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	mutex_lock(&bus->ns->lock);
	kref_init(&e->kref);
	e->mode = mode > 0 ? mode : 0600;
	e->uid = uid;
	e->gid = gid;

	e->name = kstrdup(name, GFP_KERNEL);
	if (!e->name) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	/* register minor in our endpoint map */
	i = idr_alloc(&bus->ns->idr, e, 1, 0, GFP_KERNEL);
	if (i <= 0) {
		ret = i;
		goto err_unlock;
	}
	e->minor = i;

	/* get id for this endpoint from bus */
	mutex_lock(&bus->lock);
	e->id = bus->ep_id_next++;
	mutex_unlock(&bus->lock);

	/* register bus endpoint device */
	e->dev = kzalloc(sizeof(struct device), GFP_KERNEL);
	if (!e->dev) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	dev_set_name(e->dev, "%s/%s/%s", bus->ns->devpath, bus->name, name);
	e->dev->bus = &kdbus_subsys;
	e->dev->type = &kdbus_devtype_ep;
	e->dev->devt = MKDEV(bus->ns->major, e->minor);
	dev_set_drvdata(e->dev, e);
	ret = device_register(e->dev);
	if (ret < 0) {
		put_device(e->dev);
		e->dev = NULL;
	}

	/* Link this endpoint to the bus it is on */
	e->bus = kdbus_bus_ref(bus);
	list_add_tail(&e->bus_entry, &bus->ep_list);

	/* install policy */
	e->policy_open = policy_open;
	if (!policy_open) {
		e->policy_db = kdbus_policy_db_new();
		if (!e->policy_db) {
			ret = -ENOMEM;
			goto err_unlock;
		}
	}

	init_waitqueue_head(&e->wait);
	INIT_LIST_HEAD(&e->connection_list);

	mutex_unlock(&bus->ns->lock);

	pr_info("created endpoint %llu for bus '%s/%s/%s'\n",
		(unsigned long long)e->id, bus->ns->devpath, bus->name, name);
	return 0;

err_unlock:
	mutex_unlock(&bus->ns->lock);
	kdbus_ep_unref(e);
	return ret;
}

int kdbus_ep_remove(struct kdbus_ep *ep)
{
	struct kdbus_bus *bus = ep->bus;

	mutex_lock(&bus->ns->lock);
	device_unregister(ep->dev);
	list_del(&ep->bus_entry);
	kdbus_ep_unref(ep);
	mutex_unlock(&bus->ns->lock);
	kdbus_bus_unref(bus);
	return 0;
}

int kdbus_ep_kmake_user(void __user *buf, struct kdbus_cmd_ep_kmake **kmake)
{
	u64 size;
	struct kdbus_cmd_ep_kmake *km;
	const struct kdbus_cmd_make_item *item;
	int ret;

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_ep_make))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_ep_make) || size > 0xffff)
		return -EMSGSIZE;

	km = kmalloc(sizeof(struct kdbus_cmd_ep_kmake) + size, GFP_KERNEL);
	if (!km)
		return -ENOMEM;

	memset(km, 0, offsetof(struct kdbus_cmd_ep_kmake, make));
	if (copy_from_user(&km->make, buf, size)) {
		ret = -EFAULT;
		goto out_err;
	}

	KDBUS_ITEM_FOREACH(item, &km->make) {
		/* empty data records are invalid */
		if (item->size <= KDBUS_ITEM_HEADER_SIZE) {
			ret = -EINVAL;
			goto out_err;
		}

		switch (item->type) {
		case KDBUS_CMD_MAKE_NAME:
			if (km->name) {
				ret = -EEXIST;
				goto out_err;
			}

			if (item->size < KDBUS_ITEM_HEADER_SIZE + 2) {
				ret = -EINVAL;
				goto out_err;
			}

			if (item->size > KDBUS_ITEM_HEADER_SIZE + 64) {
				ret = -ENAMETOOLONG;
				goto out_err;
			}

			if (!kdbus_validate_nul(item->str,
					item->size - KDBUS_ITEM_HEADER_SIZE)) {
				ret = -EINVAL;
				goto out_err;
			}

			km->name = item->str;
			continue;

		default:
			ret = -ENOTSUPP;
			goto out_err;
		}
	}

	/* expect correct padding and size values */
	if ((char *)item - ((char *)&km->make + km->make.size) >= 8)
		return EINVAL;

	if (!km->name) {
		ret = -EBADMSG;
		goto out_err;
	}

	*kmake = km;
	return 0;

out_err:
	return ret;
}
