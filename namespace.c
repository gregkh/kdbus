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
#include <linux/sizes.h>
#include <uapi/linux/major.h>

#include "namespace.h"

/* global list of all namespaces */
static LIST_HEAD(namespace_list);

/* namespace list lock */
DEFINE_MUTEX(kdbus_subsys_lock);

/* next namespace id sequence number */
static u64 kdbus_ns_id_next;

/* control nodes are world accessible */
static char *kdbus_devnode_control(struct device *dev, umode_t *mode,
				   kuid_t *uid, kgid_t *gid)
{
	struct kdbus_ns *ns = dev_get_drvdata(dev);

	if (mode)
		*mode = ns->mode;

	return NULL;
}

static struct device_type kdbus_devtype_control = {
	.name		= "control",
	.release	= kdbus_dev_release,
	.devnode	= kdbus_devnode_control,
};

/* kdbus namespace */
struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns)
{
	kref_get(&ns->kref);
	return ns;
}

void kdbus_ns_disconnect(struct kdbus_ns *ns)
{
	mutex_lock(&kdbus_subsys_lock);
	list_del(&ns->ns_entry);

	if (ns->dev) {
		device_unregister(ns->dev);
		ns->dev = NULL;
	}
	if (ns->major > 0) {
		idr_remove(&kdbus_ns_major_idr, ns->major);
		unregister_chrdev(ns->major, "kdbus");
		ns->major = 0;
	}
	mutex_unlock(&kdbus_subsys_lock);
	pr_debug("closing namespace %s\n", ns->devpath);
}

static void __kdbus_ns_free(struct kref *kref)
{
	struct kdbus_ns *ns = container_of(kref, struct kdbus_ns, kref);

	kdbus_ns_disconnect(ns);
	pr_debug("clean up namespace %s\n", ns->devpath);
	kfree(ns->name);
	kfree(ns->devpath);
	kfree(ns);
}

void kdbus_ns_unref(struct kdbus_ns *ns)
{
	kref_put(&ns->kref, __kdbus_ns_free);
}

static struct kdbus_ns *kdbus_ns_find(struct kdbus_ns const *parent, const char *name)
{
	struct kdbus_ns *ns = NULL;
	struct kdbus_ns *n;

	mutex_lock(&kdbus_subsys_lock);
	list_for_each_entry(n, &namespace_list, ns_entry) {
		if (n->parent != parent)
			continue;
		if (strcmp(n->name, name))
			continue;

		ns = kdbus_ns_ref(n);
		break;
	}

	mutex_unlock(&kdbus_subsys_lock);
	return ns;
}

struct kdbus_ns *kdbus_ns_find_by_major(unsigned int major)
{
	struct kdbus_ns *ns;

	mutex_lock(&kdbus_subsys_lock);
	ns = idr_find(&kdbus_ns_major_idr, major);
	mutex_unlock(&kdbus_subsys_lock);

	return ns;
}

int kdbus_ns_new(struct kdbus_ns *parent, const char *name, umode_t mode, struct kdbus_ns **ns)
{
	struct kdbus_ns *n;
	const char *ns_name = NULL;
	int i;
	int ret;

	if ((parent && !name) || (!parent && name))
		return -EINVAL;

	n = kdbus_ns_find(parent, name);
	if (n) {
		kdbus_ns_unref(n);
		return -EEXIST;
	}

	n = kzalloc(sizeof(struct kdbus_ns), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	if (name) {
		ns_name = kstrdup(name, GFP_KERNEL);
		if (!ns_name) {
			kfree(n);
			return -ENOMEM;
		}
	}

	INIT_LIST_HEAD(&n->bus_list);
	kref_init(&n->kref);
	n->mode = mode;
	idr_init(&n->idr);
	mutex_init(&n->lock);

	/* compose name and path of base directory in /dev */
	if (!parent) {
		/* initial namespace */
		n->devpath = kstrdup("kdbus", GFP_KERNEL);
		if (!n->devpath) {
			ret = -ENOMEM;
			goto ret;
		}

		/* register static major to support module auto-loading */
		ret = register_chrdev(KDBUS_CHAR_MAJOR, "kdbus", &kdbus_device_ops);
		if (ret)
			goto ret;
		n->major = KDBUS_CHAR_MAJOR;
	} else {
		n->parent = parent;
		n->devpath = kasprintf(GFP_KERNEL, "kdbus/ns/%s/%s", parent->devpath, name);
		if (!n->devpath) {
			ret = -ENOMEM;
			goto ret;
		}

		/* get dynamic major */
		n->major = register_chrdev(0, "kdbus", &kdbus_device_ops);
		if (n->major < 0) {
			ret = n->major;
			goto ret;
		}
		n->name = ns_name;
	}

	mutex_lock(&kdbus_subsys_lock);

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
	if (!n->dev)
		goto exit_unlock;
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

	list_add_tail(&n->ns_entry, &namespace_list);

	mutex_unlock(&kdbus_subsys_lock);

	*ns = n;
	pr_debug("created namespace %llu '%s/'\n",
		 (unsigned long long)n->id, n->devpath);
	return 0;

exit_unlock:
	mutex_unlock(&kdbus_subsys_lock);
ret:
	kdbus_ns_unref(n);
	return ret;
}

int kdbus_ns_kmake_user(void __user *buf, struct kdbus_cmd_ns_kmake **kmake)
{
	u64 size;
	struct kdbus_cmd_ns_kmake *km;
	const struct kdbus_item *item;
	int ret;

	if (kdbus_size_get_user(size, buf, struct kdbus_cmd_ns_make))
		return -EFAULT;

	if (size < sizeof(struct kdbus_cmd_ns_make) || size > KDBUS_MAKE_MAX_SIZE)
		return -EMSGSIZE;

	km = kmalloc(sizeof(struct kdbus_cmd_ns_kmake) + size, GFP_KERNEL);
	if (!km)
		return -ENOMEM;

	memset(km, 0, offsetof(struct kdbus_cmd_ns_kmake, make));
	if (copy_from_user(&km->make, buf, size)) {
		ret = -EFAULT;
		goto exit;
	}

	KDBUS_ITEM_FOREACH_VALIDATE(item, &km->make) {
		/* empty data records are invalid */
		if (item->size <= KDBUS_ITEM_HEADER_SIZE) {
			ret = -EINVAL;
			goto exit;
		}

		switch (item->type) {
		case KDBUS_MAKE_NAME:
			if (km->name) {
				ret = -EEXIST;
				goto exit;
			}

			if (item->size < KDBUS_ITEM_HEADER_SIZE + 2) {
				ret = -EINVAL;
				goto exit;
			}

			if (item->size > KDBUS_ITEM_HEADER_SIZE + KDBUS_MAKE_MAX_LEN + 1) {
				ret = -ENAMETOOLONG;
				goto exit;
			}

			if (!kdbus_validate_nul(item->str,
					item->size - KDBUS_ITEM_HEADER_SIZE)) {
				ret = -EINVAL;
				goto exit;
			}

			km->name = item->str;
			continue;

		default:
			ret = -ENOTSUPP;
			goto exit;
		}
	}

	/* expect correct padding and size values */
	if ((char *)item - ((char *)&km->make + km->make.size) >= 8)
		return EINVAL;

	if (!km->name) {
		ret = -EBADMSG;
		goto exit;
	}

	*kmake = km;
	return 0;

exit:
	return ret;
}
