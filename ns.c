/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/init.h>
//#include <uapi/linux/major.h>

#include "kdbus.h"

#include "kdbus_internal.h"

/* global list of all namespaces */
static LIST_HEAD(namespace_list);

/* next namespace id sequence number */
static __u64 kdbus_ns_id_next;

/* control nodes are world accessible */
static char *kdbus_devnode_control(struct device *dev, umode_t *mode
#ifdef DRIVER_CORE_DEVICE_TYPE_DEVNODE_UID
		, uid_t *uid, gid_t *gid)
#else
		)
#endif
{
	if (mode)
		*mode = 0666;
	return NULL;
}

static struct device_type kdbus_devtype_control = {
	.name		= "control",
	.release	= kdbus_release,
	.devnode	= kdbus_devnode_control,
};


/* kdbus namespace */
struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns)
{
	if (!ns)
		return NULL;
	ns->ref++;
	return ns;
}

void kdbus_ns_disconnect(struct kdbus_ns *ns)
{
	if (ns->disconnected)
		return;
	ns->disconnected = true;

	if (ns->dev) {
		device_unregister(ns->dev);
		ns->dev = NULL;
	}
	if (ns->major > 0) {
		idr_remove(&kdbus_ns_major_idr, ns->major);
		unregister_chrdev(ns->major, "kdbus");
		ns->major = 0;
	}
	pr_info("closing namespace %s\n", ns->devpath);
}

struct kdbus_ns *kdbus_ns_unref(struct kdbus_ns *ns)
{
	if (!ns)
		return NULL;
	ns->ref--;
	if (ns->ref > 0)
		return ns;

	kdbus_ns_disconnect(ns);
	pr_info("clean up namespace %s\n", ns->devpath);
	list_del(&ns->list_entry);
	kfree(ns->name);
	kfree(ns->devpath);
	kfree(ns);
	return NULL;
}

int kdbus_ns_new(struct kdbus_ns *parent, const char *name, struct kdbus_ns **ns)
{
	struct kdbus_ns *n;
	const char *ns_name = NULL;
	int i;
	int err;

	pr_info("%s, %s\n", __func__, name);

	if ((parent && !name) || (!parent && name))
		return -EINVAL;

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

	n->ref = 1;
	idr_init(&n->idr);
	mutex_init(&n->lock);

	/* compose name and path of base directory in /dev */
	if (!parent) {
		/* initial namespace */
		n->devpath = kstrdup("kdbus", GFP_KERNEL);
		if (!n->devpath) {
			err = -ENOMEM;
			goto err;
		}

		/* register static major to support module auto-loading */
		err = register_chrdev(KDBUS_CHAR_MAJOR, "kdbus", &kdbus_device_ops);
		if (err)
			goto err;
		n->major = KDBUS_CHAR_MAJOR;
	} else {
		n->parent = parent;
		n->devpath = kasprintf(GFP_KERNEL, "kdbus/ns/%s/%s", parent->devpath, name);
//		n->devpath = kasprintf(GFP_KERNEL, "kdbus/ns/%s", name);
		if (!n->devpath) {
			err = -ENOMEM;
			goto err;
		}

		/* get dynamic major */
		n->major = register_chrdev(0, "kdbus", &kdbus_device_ops);
		if (n->major < 0) {
			err = n->major;
			goto err;
		}
		n->name = ns_name;
	}

	/* register major in our namespace map */
	mutex_lock(&kdbus_subsys_lock);

	/* FIXME - is this even needed?  */
	i = idr_alloc(&kdbus_ns_major_idr, n, n->major, 0, GFP_KERNEL);
	if (i <= 0) {
		err = -EEXIST;
		goto err_unlock;
	}

	/* get id for this namespace */
	n->id = kdbus_ns_id_next++;

	/* register control device for this namespace */
	n->dev = kzalloc(sizeof(struct device), GFP_KERNEL);
	if (!n->dev)
		goto err_unlock;
	dev_set_name(n->dev, "%s/%s", n->devpath, "control");
	n->dev->bus = &kdbus_subsys;
	n->dev->type = &kdbus_devtype_control;
	n->dev->devt = MKDEV(n->major, 0);
	dev_set_drvdata(n->dev, n);
	err = device_register(n->dev);
	if (err < 0) {
		put_device(n->dev);
		n->dev = NULL;
		goto err_unlock;
	}

	/* Add to global list of namespaces so we can find it again */
	list_add_tail(&n->list_entry, &namespace_list);

	mutex_unlock(&kdbus_subsys_lock);

	*ns = n;
	pr_info("created namespace %llu '%s/'\n",
		(unsigned long long)n->id, n->devpath);
	return 0;

err_unlock:
	mutex_unlock(&kdbus_subsys_lock);
err:
	kdbus_ns_unref(n);
	return err;
}

struct kdbus_ns *kdbus_ns_find(const char *name)
{
	struct kdbus_ns *ns;

	mutex_lock(&kdbus_subsys_lock);
	list_for_each_entry(ns, &namespace_list, list_entry) {
		if (!strcmp(ns->name, name))
			goto exit;
	}
	/* namespace not found so return NULL */
	ns = NULL;
exit:
	mutex_unlock(&kdbus_subsys_lock);
	return ns;
}

