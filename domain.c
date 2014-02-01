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
#include "defaults.h"
#include "handle.h"
#include "domain.h"
#include "util.h"

/* map of majors to namespaces */
static DEFINE_IDR(kdbus_domain_major_idr);

/* next domain id sequence number */
static u64 kdbus_domain_seq_last;

/* kdbus initial domain */
struct kdbus_domain *kdbus_domain_init;

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
	struct kdbus_domain *domain = dev_get_drvdata(dev);

	if (mode)
		*mode = domain->mode;

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
 * kdbus_domain_ref() - take a domain reference
 * @domain:		Namespace
 *
 * Return: the domain itself
 */
struct kdbus_domain *kdbus_domain_ref(struct kdbus_domain *domain)
{
	kref_get(&domain->kref);
	return domain;
}

/**
 * kdbus_domain_disconnect() - invalidate a domain
 * @domain:		Namespace
 */
void kdbus_domain_disconnect(struct kdbus_domain *domain)
{
	struct kdbus_bus *bus, *tmp;

	mutex_lock(&domain->lock);
	if (domain->disconnected) {
		mutex_unlock(&domain->lock);
		return;
	}

	domain->disconnected = true;
	mutex_unlock(&domain->lock);

	mutex_lock(&kdbus_subsys_lock);
	if (domain->parent)
		list_del(&domain->domain_entry);
	mutex_unlock(&kdbus_subsys_lock);

	/* remove any buses attached to this endpoint */
	list_for_each_entry_safe(bus, tmp, &domain->bus_list, domain_entry) {
		kdbus_bus_disconnect(bus);
		kdbus_bus_unref(bus);
	}

	if (domain->dev) {
		device_unregister(domain->dev);
		domain->dev = NULL;
	}
	if (domain->major > 0) {
		idr_remove(&kdbus_domain_major_idr, domain->major);
		unregister_chrdev(domain->major, KBUILD_MODNAME);
		domain->major = 0;
	}
}

static void __kdbus_domain_free(struct kref *kref)
{
	struct kdbus_domain *domain =
		container_of(kref, struct kdbus_domain, kref);

	kdbus_domain_disconnect(domain);
	kdbus_domain_unref(domain->parent);
	kfree(domain->name);
	kfree(domain->devpath);
	kfree(domain);
}

/**
 * kdbus_domain_unref() - drop a domain reference
 * @domain:		Namespace
 *
 * When the last reference is dropped, the domain internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_domain *kdbus_domain_unref(struct kdbus_domain *domain)
{
	if (!domain)
		return NULL;

	kref_put(&domain->kref, __kdbus_domain_free);
	return NULL;
}

static struct kdbus_domain *kdbus_domain_find(struct kdbus_domain const *parent,
				      const char *name)
{
	struct kdbus_domain *domain = NULL;
	struct kdbus_domain *n;

	list_for_each_entry(n, &parent->ns_list, domain_entry) {
		if (strcmp(n->name, name))
			continue;

		domain = kdbus_domain_ref(n);
		break;
	}

	return domain;
}

/**
 * kdbus_domain_find_by_major() - lookup a domain by its major device number
 * @major:		Major number
 *
 * Looks up a domain by major number. The returned namspace
 * is ref'ed, and needs to be unref'ed by the user. Returns NULL if
 * the namepace can't be found.
 *
 * Return: the domain, or NULL if not found
 */
struct kdbus_domain *kdbus_domain_find_by_major(unsigned int major)
{
	struct kdbus_domain *domain;

	mutex_lock(&kdbus_subsys_lock);
	domain = idr_find(&kdbus_domain_major_idr, major);
	if (domain)
		kdbus_domain_ref(domain);
	mutex_unlock(&kdbus_subsys_lock);

	return domain;
}

/**
 * kdbus_domain_new() - create a new domain
 * @parent:		Parent domain, NULL for initial one
 * @name:		Name of the domain, NULL for the initial one
 * @mode:		The access mode for the "control" device node
 * @domain:			The returned domain
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_domain_new(struct kdbus_domain *parent, const char *name, umode_t mode,
		 struct kdbus_domain **domain)
{
	struct kdbus_domain *n;
	int ret;

	BUG_ON(*domain);

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
		/* initial domain */
		n->devpath = kstrdup(KBUILD_MODNAME, GFP_KERNEL);
		if (!n->devpath) {
			ret = -ENOMEM;
			goto exit_unlock;
		}
	} else {
		struct kdbus_domain *exists;

		exists = kdbus_domain_find(parent, name);
		if (exists) {
			kdbus_domain_unref(exists);
			ret = -EEXIST;
			goto exit_unlock;
		}

		n->devpath = kasprintf(GFP_KERNEL, "%s/domain/%s",
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
	 * kdbus_device_ops' dev_t finds the domain in the major map,
	 * and the bus in the minor map of that domain
	 */
	ret = idr_alloc(&kdbus_domain_major_idr, n, n->major, 0, GFP_KERNEL);
	if (ret < 0) {
		if (ret == -ENOSPC)
			ret = -EEXIST;
		goto exit_unlock;
	}

	/* get id for this domain */
	n->id = ++kdbus_domain_seq_last;

	/* register control device for this domain */
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

	/* link into parent domain */
	if (parent) {
		n->parent = kdbus_domain_ref(parent);
		list_add_tail(&n->domain_entry, &parent->ns_list);
	}
	mutex_unlock(&kdbus_subsys_lock);

	*domain = n;
	return 0;

exit_unlock:
	mutex_unlock(&kdbus_subsys_lock);
	kdbus_domain_unref(n);
	return ret;
}

/**
 * kdbus_domain_make_user() - create domain data from user data
 * @cmd:		The command as passed in by the ioctl
 * @name:		The name of the domain to create
 *
 * Return: 0 on success, negative errno on failure
 */
int kdbus_domain_make_user(struct kdbus_cmd_make *cmd, char **name)
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

/**
 * kdbus_domain_user_ref() - get a kdbus_domain_user object in a domain
 * @domain:		The domain
 * @uid:	The uid of the user
 *
 * Return: a kdbus_domain_user, either freshly allocated or with the reference
 * counter increased. In case of memory allocation failure, NULL is returned.
 */
struct kdbus_domain_user *kdbus_domain_user_ref(struct kdbus_domain *domain, kuid_t uid)
{
	struct kdbus_domain_user *u;

	/* find uid and reference it */
	mutex_lock(&domain->lock);
	hash_for_each_possible(domain->user_hash, u, hentry, __kuid_val(uid)) {
		if (!uid_eq(u->uid, uid))
			continue;

		kref_get(&u->kref);
		mutex_unlock(&domain->lock);
		return u;
	}
	mutex_unlock(&domain->lock);

	/* allocate a new user */
	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return NULL;

	kref_init(&u->kref);
	u->domain = kdbus_domain_ref(domain);
	u->uid = uid;
	atomic_set(&u->buses, 0);
	atomic_set(&u->connections, 0);

	/* link into domain */
	mutex_lock(&domain->lock);
	hash_add(domain->user_hash, &u->hentry, __kuid_val(u->uid));
	mutex_unlock(&domain->lock);

	return u;
}

static void __kdbus_domain_user_free(struct kref *kref)
{
	struct kdbus_domain_user *user = container_of(kref, struct kdbus_domain_user,
						  kref);

	BUG_ON(atomic_read(&user->buses) > 0);
	BUG_ON(atomic_read(&user->connections) > 0);

	mutex_lock(&user->domain->lock);
	hash_del(&user->hentry);
	mutex_unlock(&user->domain->lock);
	kdbus_domain_unref(user->domain);
	kfree(user);
}

struct kdbus_domain_user *kdbus_domain_user_unref(struct kdbus_domain_user *user)
{
	kref_put(&user->kref, __kdbus_domain_user_free);
	return NULL;
}
