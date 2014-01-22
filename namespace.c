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

#include "defaults.h"
#include "util.h"
#include "bus.h"
#include "handle.h"
#include "namespace.h"

/* map of majors to namespaces */
static DEFINE_IDR(kdbus_ns_major_idr);

/* next namespace id sequence number */
static u64 kdbus_ns_seq_last;

/* kdbus initial namespace */
struct kdbus_ns *kdbus_ns_init;

/* kdbus subsystem lock */
static DEFINE_MUTEX(kdbus_subsys_lock);

/* kdbus sysfs subsystem */
struct bus_type kdbus_subsys = {
	.name = KBUILD_MODNAME,
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
 * kdbus_ns_ref() - take a namespace reference
 * @ns	:		Namespace
 *
 * Return: the namespace itself
 */
struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns)
{
	kref_get(&ns->kref);
	return ns;
}

/**
 * kdbus_ns_disconnect() - invalidate a namespace
 * @ns	:		Namespace
 */
void kdbus_ns_disconnect(struct kdbus_ns *ns)
{
	struct kdbus_bus *bus, *tmp;

	mutex_lock(&ns->lock);
	if (ns->disconnected) {
		mutex_unlock(&ns->lock);
		return;
	}

	ns->disconnected = true;
	mutex_unlock(&ns->lock);

	mutex_lock(&kdbus_subsys_lock);
	if (ns->parent)
		list_del(&ns->ns_entry);
	mutex_unlock(&kdbus_subsys_lock);

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
		unregister_chrdev(ns->major, KBUILD_MODNAME);
		ns->major = 0;
	}
}

static void __kdbus_ns_free(struct kref *kref)
{
	struct kdbus_ns *ns = container_of(kref, struct kdbus_ns, kref);

	kdbus_ns_disconnect(ns);
	kdbus_ns_unref(ns->parent);
	kfree(ns->name);
	kfree(ns->devpath);
	kfree(ns);
}

/**
 * kdbus_ns_unref() - drop a namespace reference
 * @ns	:		Namespace
 *
 * When the last reference is dropped, the namespace internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_ns *kdbus_ns_unref(struct kdbus_ns *ns)
{
	if (!ns)
		return NULL;

	kref_put(&ns->kref, __kdbus_ns_free);
	return NULL;
}

static struct kdbus_ns *kdbus_ns_find(struct kdbus_ns const *parent,
				      const char *name)
{
	struct kdbus_ns *ns = NULL;
	struct kdbus_ns *n;

	list_for_each_entry(n, &parent->ns_list, ns_entry) {
		if (strcmp(n->name, name))
			continue;

		ns = kdbus_ns_ref(n);
		break;
	}

	return ns;
}

/**
 * kdbus_ns_find_by_major() - lookup a namespace by its major device number
 * @major:		Major number
 *
 * Looks up a namespace by major number. The returned namspace
 * is ref'ed, and needs to be unref'ed by the user. Returns NULL if
 * the namepace can't be found.
 *
 * Return: the namespace, or NULL if not found
 */
struct kdbus_ns *kdbus_ns_find_by_major(unsigned int major)
{
	struct kdbus_ns *ns;

	mutex_lock(&kdbus_subsys_lock);
	ns = idr_find(&kdbus_ns_major_idr, major);
	if (ns)
		kdbus_ns_ref(ns);
	mutex_unlock(&kdbus_subsys_lock);

	return ns;
}

/**
 * kdbus_ns_new() - create a new namespace
 * @parent:		Parent namespace, NULL for initial one
 * @name:		Name of the namespace, NULL for the initial one
 * @mode:		The access mode for the "control" device node
 * @ns:			The returned namespace
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_ns_new(struct kdbus_ns *parent, const char *name, umode_t mode,
		 struct kdbus_ns **ns)
{
	struct kdbus_ns *n;
	int ret;

	BUG_ON(*ns);

	if ((parent && !name) || (!parent && name))
		return -EINVAL;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	INIT_LIST_HEAD(&n->bus_list);
	INIT_LIST_HEAD(&n->ns_list);
	kref_init(&n->kref);
	n->mode = mode;
	idr_init(&n->idr);
	mutex_init(&n->lock);
	atomic64_set(&n->msg_seq_last, 0);

	mutex_lock(&kdbus_subsys_lock);

	/* compose name and path of base directory in /dev */
	if (!parent) {
		/* initial namespace */
		n->devpath = kstrdup(KBUILD_MODNAME, GFP_KERNEL);
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

		n->devpath = kasprintf(GFP_KERNEL, "%s/ns/%s",
				       parent->devpath, name);
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
	ret = register_chrdev(0, KBUILD_MODNAME, &kdbus_device_ops);
	if (ret < 0)
		goto exit_unlock;

	n->major = ret;

	/*
	 * kdbus_device_ops' dev_t finds the namespace in the major map,
	 * and the bus in the minor map of that namespace
	 */
	ret = idr_alloc(&kdbus_ns_major_idr, n, n->major, 0, GFP_KERNEL);
	if (ret < 0) {
		if (ret == -ENOSPC)
			ret = -EEXIST;
		goto exit_unlock;
	}

	/* get id for this namespace */
	n->id = ++kdbus_ns_seq_last;

	/* register control device for this namespace */
	n->dev = kzalloc(sizeof(*n->dev), GFP_KERNEL);
	if (!n->dev) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	dev_set_name(n->dev, "%s/control", n->devpath);
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

	/* link into parent namespace */
	if (parent) {
		n->parent = kdbus_ns_ref(parent);
		list_add_tail(&n->ns_entry, &parent->ns_list);
	}
	mutex_unlock(&kdbus_subsys_lock);

	*ns = n;
	return 0;

exit_unlock:
	mutex_unlock(&kdbus_subsys_lock);
	kdbus_ns_unref(n);
	return ret;
}

/**
 * kdbus_ns_make_user() - create namespace data from user data
 * @cmd:		The command as passed in by the ioctl
 * @name:		The name of the namespace to create
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_ns_make_user(struct kdbus_cmd_make *cmd, char **name)
{
	const struct kdbus_item *item;
	const char *n = NULL;
	int ret;

	KDBUS_ITEM_FOREACH(item, cmd, items) {
		size_t payload_size;

		if (!KDBUS_ITEM_VALID(item, cmd))
			return -EINVAL;

		payload_size = item->size - KDBUS_ITEM_HEADER_SIZE;

		switch (item->type) {
		case KDBUS_ITEM_MAKE_NAME:
			if (n)
				return -EEXIST;

			if (payload_size < 2)
				return -EINVAL;

			if (payload_size > KDBUS_SYSNAME_MAX_LEN + 1)
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

	if (!KDBUS_ITEM_END(item, cmd))
		return -EINVAL;

	if (!name)
		return -EBADMSG;

	*name = (char *)n;
	return 0;
}

struct kdbus_ns_user *kdbus_ns_user_ref(struct kdbus_ns *ns, kuid_t uid)
{
	struct kdbus_ns_user *u;

	/* find uid and reference it */
	mutex_lock(&ns->lock);
	hash_for_each_possible(ns->user_hash, u, hentry, __kuid_val(uid)) {
		if (!uid_eq(u->uid, uid))
			continue;

		kref_get(&u->kref);
		mutex_unlock(&ns->lock);
		return u;
	}
	mutex_unlock(&ns->lock);

	/* allocate a new user */
	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return NULL;

	kref_init(&u->kref);
	u->ns = kdbus_ns_ref(ns);
	u->uid = uid;
	atomic_set(&u->buses, 0);
	atomic_set(&u->connections, 0);

	/* link into namespace */
	mutex_lock(&ns->lock);
	hash_add(ns->user_hash, &u->hentry, __kuid_val(u->uid));
	mutex_unlock(&ns->lock);

	return u;
}

static void __kdbus_ns_user_free(struct kref *kref)
{
	struct kdbus_ns_user *user = container_of(kref, struct kdbus_ns_user,
						  kref);

	BUG_ON(atomic_read(&user->buses) > 0);
	BUG_ON(atomic_read(&user->connections) > 0);

	mutex_lock(&user->ns->lock);
	hash_del(&user->hentry);
	mutex_unlock(&user->ns->lock);
	kdbus_ns_unref(user->ns);
	kfree(user);
}

struct kdbus_ns_user *kdbus_ns_user_unref(struct kdbus_ns_user *user)
{
	kref_put(&user->kref, __kdbus_ns_user_free);
	return NULL;
}
