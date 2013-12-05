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

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/sizes.h>

#include "handle.h"
#include "namespace.h"
#include "bus.h"

/* global list of all namespaces */
static LIST_HEAD(namespace_list);

/* map of majors to namespaces */
static DEFINE_IDR(kdbus_ns_major_idr);

/* next namespace id sequence number */
static u64 kdbus_ns_id_next;

/* kdbus initial namespace */
struct kdbus_ns *kdbus_ns_init;

/* kdbus subsystem lock */
static DEFINE_MUTEX(kdbus_subsys_lock);

/* kdbus sysfs subsystem */
struct bus_type kdbus_subsys = {
	.name = "kdbus",
};

/* control nodes are world accessible */
static char *kdbus_devnode_control(struct device *dev, umode_t *mode,
				   kuid_t *uid, kgid_t *gid)
{
	struct kdbus_ns *ns = dev_get_drvdata(dev);

	if (mode)
		*mode = ns->mode;

	return NULL;
}

static void kdbus_dev_release(struct device *dev)
{
	kfree(dev);
}

static struct device_type kdbus_devtype_control = {
	.name		= "control",
	.release	= kdbus_dev_release,
	.devnode	= kdbus_devnode_control,
};

/**
 * kdbus_ns_ref - take a namespace reference
 * @ns	:		Namespace
 *
 * Returns: the namespace itself
 */
struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns)
{
	kref_get(&ns->kref);
	return ns;
}

/**
 * kdbus_ns_disconnect - invalidate a namespace
 * @ns	:		Namespace
 */
void kdbus_ns_disconnect(struct kdbus_ns *ns)
{
	struct kdbus_bus *bus, *tmp;

	mutex_lock(&kdbus_subsys_lock);

	if (ns->disconnected)
		goto exit_unlock;
	ns->disconnected = true;

	list_del(&ns->namespace_entry);

	/* remove any buses attached to this endpoint */
	list_for_each_entry_safe(bus, tmp, &ns->bus_list, ns_entry) {
		kdbus_bus_disconnect(bus);
		kdbus_bus_unref(bus);
	}

	if (ns->dev) {
		device_unregister(ns->dev);
		ns->dev = NULL;
	}
	if (ns->major > 0) {
		idr_remove(&kdbus_ns_major_idr, ns->major);
		unregister_chrdev(ns->major, "kdbus");
		ns->major = 0;
	}

exit_unlock:
	mutex_unlock(&kdbus_subsys_lock);
}

static void __kdbus_ns_free(struct kref *kref)
{
	struct kdbus_ns *ns = container_of(kref, struct kdbus_ns, kref);

	kdbus_ns_disconnect(ns);
	kfree(ns->name);
	kfree(ns->devpath);
	kfree(ns);
}

/**
 * kdbus_ns_unref - drop a namespace reference
 * @ns	:		Namespace
 *
 * When the last reference is dropped, the namespace internal structure
 * is freed.
 */
void kdbus_ns_unref(struct kdbus_ns *ns)
{
	kref_put(&ns->kref, __kdbus_ns_free);
}

static struct kdbus_ns *kdbus_ns_find(struct kdbus_ns const *parent, const char *name)
{
	struct kdbus_ns *ns = NULL;
	struct kdbus_ns *n;

	list_for_each_entry(n, &namespace_list, namespace_entry) {
		if (n->parent != parent)
			continue;
		if (strcmp(n->name, name))
			continue;

		ns = kdbus_ns_ref(n);
		break;
	}

	return ns;
}

/**
 * kdbus_ns_find_by_major - lookup a namespace by its major device number
 * @major:		Major number
 *
 * Returns: the namespace, or NULL if not found
 */
struct kdbus_ns *kdbus_ns_find_by_major(unsigned int major)
{
	struct kdbus_ns *ns;

	mutex_lock(&kdbus_subsys_lock);
	ns = idr_find(&kdbus_ns_major_idr, major);
	mutex_unlock(&kdbus_subsys_lock);

	return ns;
}

/**
 * kdbus_ns_new - create a new namespace
 * @parent:		Parent namespace, NULL for initial one
 * @name:		Name of the namespace, NULL for the initial one
 * @mode:		The access mode for the "control" device node
 * @ns:			The returned namespace
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_ns_new(struct kdbus_ns *parent, const char *name, umode_t mode, struct kdbus_ns **ns)
{
	struct kdbus_ns *n;
	int i;
	int ret;

	if ((parent && !name) || (!parent && name))
		return -EINVAL;

	n = kzalloc(sizeof(struct kdbus_ns), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	INIT_LIST_HEAD(&n->bus_list);
	kref_init(&n->kref);
	n->mode = mode;
	idr_init(&n->idr);
	mutex_init(&n->lock);

	mutex_lock(&kdbus_subsys_lock);

	/* compose name and path of base directory in /dev */
	if (!parent) {
		/* initial namespace */
		n->devpath = kstrdup("kdbus", GFP_KERNEL);
		if (!n->devpath) {
			ret = -ENOMEM;
			goto exit_unlock;
		}
	} else {
		struct kdbus_ns *exists;

		exists = kdbus_ns_find(parent, name);
		if (exists) {
			kdbus_ns_unref(exists);
			ret = -EEXIST;
			goto exit_unlock;
		}

		n->parent = parent;
		n->devpath = kasprintf(GFP_KERNEL, "%s/ns/%s", parent->devpath, name);
		if (!n->devpath) {
			ret = -ENOMEM;
			goto exit_unlock;
		}

		n->name = kstrdup(name, GFP_KERNEL);
		if (!n->name) {
			ret = -ENOMEM;
			goto exit_unlock;
		}
	}

	/* get dynamic major */
	n->major = register_chrdev(0, "kdbus", &kdbus_device_ops);
	if (n->major < 0) {
		ret = n->major;
		goto exit_unlock;
	}

	/* kdbus_device_ops' dev_t finds the namespace in the major map,
	 * and the bus in the minor map of that namespace */
	i = idr_alloc(&kdbus_ns_major_idr, n, n->major, 0, GFP_KERNEL);
	if (i <= 0) {
		ret = -EEXIST;
		goto exit_unlock;
	}

	/* get id for this namespace */
	n->id = kdbus_ns_id_next++;

	/* register control device for this namespace */
	n->dev = kzalloc(sizeof(struct device), GFP_KERNEL);
	if (!n->dev) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	dev_set_name(n->dev, "%s/%s", n->devpath, "control");
	n->dev->bus = &kdbus_subsys;
	n->dev->type = &kdbus_devtype_control;
	n->dev->devt = MKDEV(n->major, 0);
	dev_set_drvdata(n->dev, n);
	ret = device_register(n->dev);
	if (ret < 0) {
		put_device(n->dev);
		n->dev = NULL;
		goto exit_unlock;
	}

	list_add_tail(&n->namespace_entry, &namespace_list);
	mutex_unlock(&kdbus_subsys_lock);

	*ns = n;
	return 0;

exit_unlock:
	mutex_unlock(&kdbus_subsys_lock);
	kdbus_ns_unref(n);
	return ret;
}

/**
 * kdbus_ns_make_user - create a new namespace from user data
 * @buf:		User data
 * @make:		The returned copy of user data
 * @name:		The name of the namespace to create
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_ns_make_user(void __user *buf,
			struct kdbus_cmd_ns_make **make, char **name)
{
	u64 size;
	struct kdbus_cmd_ns_make *m;
	const struct kdbus_item *item;
	const char *n = NULL;
	int ret;

	if (kdbus_size_get_user(&size, buf, struct kdbus_cmd_ns_make))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_ns_make) || size > KDBUS_MAKE_MAX_SIZE)
		return -EMSGSIZE;

	m = memdup_user(buf, size);
	if (IS_ERR(m)) {
		ret = PTR_ERR(m);
		goto exit;
	}

	KDBUS_PART_FOREACH(item, m, items) {
		if (!KDBUS_PART_VALID(item, m)) {
			ret = -EINVAL;
			goto exit;
		}

		switch (item->type) {
		case KDBUS_MAKE_NAME:
			if (n) {
				ret = -EEXIST;
				goto exit;
			}

			if (item->size < KDBUS_PART_HEADER_SIZE + 2) {
				ret = -EINVAL;
				goto exit;
			}

			if (item->size > KDBUS_PART_HEADER_SIZE + KDBUS_MAKE_MAX_LEN + 1) {
				ret = -ENAMETOOLONG;
				goto exit;
			}

			if (!kdbus_validate_nul(item->str,
					item->size - KDBUS_PART_HEADER_SIZE)) {
				ret = -EINVAL;
				goto exit;
			}

			n = item->str;
			continue;

		default:
			ret = -ENOTSUPP;
			goto exit;
		}
	}

	if (!KDBUS_PART_END(item, m))
		return -EINVAL;

	if (!name) {
		ret = -EBADMSG;
		goto exit;
	}

	*make = m;
	*name = (char *)n;
	return 0;

exit:
	kfree(m);
	return ret;
}
