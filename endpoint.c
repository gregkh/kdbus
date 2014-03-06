/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "bus.h"
#include "endpoint.h"
#include "domain.h"
#include "policy.h"

/* endpoints are by default owned by the bus owner */
static char *kdbus_devnode_ep(struct device *dev, umode_t *mode,
			      kuid_t *uid, kgid_t *gid)
{
	struct kdbus_ep *ep = dev_get_drvdata(dev);

	if (mode)
		*mode = ep->mode;
	if (uid)
		*uid = ep->uid;
	if (gid)
		*gid = ep->gid;

	return NULL;
}

static void kdbus_dev_release(struct device *dev)
{
	kfree(dev);
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

/**
 * kdbus_ep_disconnect() - disconnect an endpoint
 * @ep:			Endpoint
 */
void kdbus_ep_disconnect(struct kdbus_ep *ep)
{
	mutex_lock(&ep->lock);
	if (ep->disconnected) {
		mutex_unlock(&ep->lock);
		return;
	}
	ep->disconnected = true;
	mutex_unlock(&ep->lock);

	/* disconnect from bus */
	mutex_lock(&ep->bus->lock);
	list_del(&ep->bus_entry);
	mutex_unlock(&ep->bus->lock);

	if (ep->dev) {
		device_unregister(ep->dev);
		ep->dev = NULL;
	}
	if (ep->minor > 0) {
		idr_remove(&ep->bus->domain->idr, ep->minor);
		ep->minor = 0;
	}

	/*
	 * wake up the queue so the connections can report
	 * POLLERR to their users.
	 */
	wake_up_interruptible(&ep->wait);
}

static void __kdbus_ep_free(struct kref *kref)
{
	struct kdbus_ep *ep = container_of(kref, struct kdbus_ep, kref);

	kdbus_ep_disconnect(ep);
	kdbus_policy_db_free(ep->policy_db);
	kdbus_bus_unref(ep->bus);
	kdbus_domain_user_unref(ep->user);
	kfree(ep->name);
	kfree(ep);
}

struct kdbus_ep *kdbus_ep_unref(struct kdbus_ep *ep)
{
	if (!ep)
		return NULL;

	kref_put(&ep->kref, __kdbus_ep_free);
	return NULL;
}

static struct kdbus_ep *kdbus_ep_find(struct kdbus_bus *bus, const char *name)
{
	struct kdbus_ep *e, *ep = NULL;

	mutex_lock(&bus->lock);
	list_for_each_entry(e, &bus->ep_list, bus_entry) {
		if (strcmp(e->name, name) != 0)
			continue;

		ep = kdbus_ep_ref(e);
	}
	mutex_unlock(&bus->lock);

	return ep;
}

/**
 * kdbus_ep_new() - create a new endpoint
 * @bus:		The bus this endpoint will be created for
 * @name:		The name of the endpoint
 * @mode:		The access mode for the device node
 * @uid:		The uid of the device node
 * @gid:		The gid of the device node
 * @policy_open:	Default policy of allow or deny
 * @ep:			Pointer to a reference where the new endpoint is stored
 *
 * This function will create a new enpoint with the given
 * name and properties for a given bus.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_ep_new(struct kdbus_bus *bus, const char *name,
		 umode_t mode, kuid_t uid, kgid_t gid,
		 bool policy_open, struct kdbus_ep **ep)
{
	struct kdbus_ep *e;
	int ret;

	e = kdbus_ep_find(bus, name);
	if (e) {
		kdbus_ep_unref(e);
		return -EEXIST;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	mutex_init(&e->lock);
	kref_init(&e->kref);
	e->uid = uid;
	e->gid = gid;
	e->mode = mode;
	init_waitqueue_head(&e->wait);

	e->name = kstrdup(name, GFP_KERNEL);
	if (!e->name) {
		ret = -ENOMEM;
		goto exit_free;
	}

	mutex_lock(&bus->domain->lock);
	/* register minor in our endpoint map */
	ret = idr_alloc(&bus->domain->idr, e, 1, 0, GFP_KERNEL);
	if (ret < 0) {
		if (ret == -ENOSPC)
			ret = -EEXIST;
		mutex_unlock(&bus->domain->lock);
		goto exit_free_name;
	}
	e->minor = ret;
	mutex_unlock(&bus->domain->lock);

	/* register bus endpoint device */
	e->dev = kzalloc(sizeof(*e->dev), GFP_KERNEL);
	if (!e->dev) {
		ret = -ENOMEM;
		goto exit_idr;
	}

	dev_set_name(e->dev, "%s/%s/%s", bus->domain->devpath, bus->name, name);
	e->dev->bus = &kdbus_subsys;
	e->dev->type = &kdbus_devtype_ep;
	e->dev->devt = MKDEV(bus->domain->major, e->minor);
	dev_set_drvdata(e->dev, e);
	ret = device_register(e->dev);
	if (ret < 0) {
		put_device(e->dev);
		e->dev = NULL;
		goto exit_idr;
	}

	/* install policy */
	e->policy_open = policy_open;
	if (!policy_open) {
		ret = kdbus_policy_db_new(&e->policy_db);
		if (ret < 0)
			goto exit_dev_unregister;
	}

	/* link into bus  */
	mutex_lock(&bus->lock);
	e->id = ++bus->ep_seq_last;
	e->bus = kdbus_bus_ref(bus);
	list_add_tail(&e->bus_entry, &bus->ep_list);
	mutex_unlock(&bus->lock);

	if (ep)
		*ep = e;
	return 0;

exit_dev_unregister:
	device_unregister(e->dev);
exit_idr:
	mutex_lock(&bus->domain->lock);
	idr_remove(&bus->domain->idr, e->minor);
	mutex_unlock(&bus->domain->lock);
exit_free_name:
	kfree(e->name);
exit_free:
	kfree(e);
	return ret;
}

/**
 * kdbus_ep_make_user() - create endpoint data from user data
 * @make:		The returned copy of user data
 * @name:		The name of the endpoint to create
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_ep_make_user(struct kdbus_cmd_make *make, char **name)
{
	const struct kdbus_item *item;
	const char *n = NULL;
	int ret;

	KDBUS_ITEM_FOREACH(item, make, items) {
		if (!KDBUS_ITEM_VALID(item, make))
			return -EINVAL;

		switch (item->type) {
		case KDBUS_ITEM_MAKE_NAME:
			if (n)
				return -EEXIST;

			if (item->size < KDBUS_ITEM_HEADER_SIZE + 2)
				return -EINVAL;

			if (item->size > KDBUS_ITEM_HEADER_SIZE +
					 KDBUS_SYSNAME_MAX_LEN + 1)
				return -ENAMETOOLONG;

			if (!kdbus_item_validate_nul(item))
				return -EINVAL;

			ret = kdbus_sysname_is_valid(item->str);
			if (ret < 0)
				return ret;

			n = item->str;
			continue;
		}
	}

	if (!KDBUS_ITEM_END(item, make))
		return -EINVAL;

	if (!n)
		return -EBADMSG;

	*name = (char *)n;
	return 0;
}
