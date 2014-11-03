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
#include "domain.h"
#include "handle.h"
#include "item.h"
#include "limits.h"
#include "util.h"

/* previous domain id sequence number */
static atomic64_t kdbus_domain_seq_last;

/* kdbus sysfs subsystem */
struct bus_type kdbus_subsys = {
	.name = KBUILD_MODNAME,
};

/* control nodes are world accessible */
static char *kdbus_devnode_control(struct device *dev, umode_t *mode,
				   kuid_t *uid, kgid_t *gid)
{
	struct kdbus_domain *domain = container_of(dev, struct kdbus_domain,
						   dev);

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
 * @domain:		Domain
 *
 * Return: the domain itself
 */
struct kdbus_domain *kdbus_domain_ref(struct kdbus_domain *domain)
{
	get_device(&domain->dev);
	return domain;
}

/**
 * kdbus_domain_disconnect() - invalidate a domain
 * @domain:		Domain
 */
void kdbus_domain_disconnect(struct kdbus_domain *domain)
{
	mutex_lock(&domain->lock);
	if (domain->disconnected) {
		mutex_unlock(&domain->lock);
		return;
	}
	domain->disconnected = true;
	mutex_unlock(&domain->lock);

	/* disconnect from parent domain */
	if (domain->parent) {
		mutex_lock(&domain->parent->lock);
		list_del(&domain->domain_entry);
		mutex_unlock(&domain->parent->lock);
	}

	if (device_is_registered(&domain->dev))
		device_del(&domain->dev);

	kdbus_minor_set(domain->dev.devt, KDBUS_MINOR_CONTROL, NULL);

	/* disconnect all sub-domains */
	for (;;) {
		struct kdbus_domain *dom;

		mutex_lock(&domain->lock);
		dom = list_first_entry_or_null(&domain->domain_list,
					       struct kdbus_domain,
					       domain_entry);
		if (!dom) {
			mutex_unlock(&domain->lock);
			break;
		}

		/* take reference, release lock, disconnect without lock */
		kdbus_domain_ref(dom);
		mutex_unlock(&domain->lock);

		kdbus_domain_disconnect(dom);
		kdbus_domain_unref(dom);
	}

	/* disconnect all buses in this domain */
	for (;;) {
		struct kdbus_bus *bus;

		mutex_lock(&domain->lock);
		bus = list_first_entry_or_null(&domain->bus_list,
					       struct kdbus_bus,
					       domain_entry);
		if (!bus) {
			mutex_unlock(&domain->lock);
			break;
		}

		/* take reference, release lock, disconnect without lock */
		kdbus_bus_ref(bus);
		mutex_unlock(&domain->lock);

		kdbus_bus_disconnect(bus);
		kdbus_bus_unref(bus);
	}
}

static void __kdbus_domain_free(struct device *dev)
{
	struct kdbus_domain *domain = container_of(dev, struct kdbus_domain,
						   dev);

	BUG_ON(!domain->disconnected);
	BUG_ON(!list_empty(&domain->domain_list));
	BUG_ON(!list_empty(&domain->bus_list));
	BUG_ON(!hash_empty(domain->user_hash));

	kdbus_minor_free(domain->dev.devt);
	kdbus_domain_unref(domain->parent);
	idr_destroy(&domain->user_idr);
	kfree(domain->name);
	kfree(domain->devpath);
	kfree(domain);
}

/**
 * kdbus_domain_unref() - drop a domain reference
 * @domain:		Domain
 *
 * When the last reference is dropped, the domain internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_domain *kdbus_domain_unref(struct kdbus_domain *domain)
{
	if (domain)
		put_device(&domain->dev);
	return NULL;
}

static struct kdbus_domain *kdbus_domain_find(struct kdbus_domain *parent,
					      const char *name)
{
	struct kdbus_domain *n;

	list_for_each_entry(n, &parent->domain_list, domain_entry)
		if (!strcmp(n->name, name))
			return n;

	return NULL;
}

/**
 * kdbus_domain_new() - create a new domain
 * @parent:		Parent domain, NULL for initial one
 * @name:		Name of the domain, NULL for the initial one
 * @mode:		The access mode for the "control" device node
 *
 * Return: a new kdbus_domain on success, ERR_PTR on failure
 */
struct kdbus_domain *kdbus_domain_new(struct kdbus_domain *parent,
				      const char *name, umode_t mode)
{
	struct kdbus_domain *d;
	int ret;

	if ((parent && !name) || (!parent && name))
		return ERR_PTR(-EINVAL);

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return ERR_PTR(-ENOMEM);

	d->disconnected = true;
	INIT_LIST_HEAD(&d->bus_list);
	INIT_LIST_HEAD(&d->domain_list);
	d->mode = mode;
	mutex_init(&d->lock);
	atomic64_set(&d->msg_seq_last, 0);
	idr_init(&d->user_idr);

	device_initialize(&d->dev);
	d->dev.bus = &kdbus_subsys;
	d->dev.type = &kdbus_devtype_control;
	d->dev.release = __kdbus_domain_free;

	/* compose name and path of base directory in /dev */
	if (parent) {
		d->devpath = kasprintf(GFP_KERNEL, "%s/domain/%s",
				       parent->devpath, name);
		if (!d->devpath) {
			ret = -ENOMEM;
			goto exit_put;
		}

		d->name = kstrdup(name, GFP_KERNEL);
		if (!d->name) {
			ret = -ENOMEM;
			goto exit_put;
		}
	} else {
		/* initial domain */
		d->devpath = kstrdup(KBUILD_MODNAME, GFP_KERNEL);
		if (!d->devpath) {
			ret = -ENOMEM;
			goto exit_put;
		}
	}

	ret = dev_set_name(&d->dev, "%s/control", d->devpath);
	if (ret < 0)
		goto exit_put;

	ret = kdbus_minor_alloc(KDBUS_MINOR_CONTROL, NULL, &d->dev.devt);
	if (ret < 0)
		goto exit_put;

	if (parent) {
		/* lock order: parent domain -> domain */
		mutex_lock(&parent->lock);

		if (parent->disconnected) {
			mutex_unlock(&parent->lock);
			ret = -ESHUTDOWN;
			goto exit_put;
		}

		if (kdbus_domain_find(parent, name)) {
			mutex_unlock(&parent->lock);
			ret = -EEXIST;
			goto exit_put;
		}

		d->parent = kdbus_domain_ref(parent);
		list_add_tail(&d->domain_entry, &parent->domain_list);
	}

	d->id = atomic64_inc_return(&kdbus_domain_seq_last);

	/*
	 * We have to mark the domain as enabled _before_ running device_add().
	 * Otherwise, there's a race between UEVENT_ADD (generated by
	 * device_add()) and us enabling the minor.
	 * However, this means user-space can open the minor before we called
	 * device_add(). This is fine, as we never require the device to be
	 * registered, anyway.
	 */

	d->disconnected = false;
	kdbus_minor_set_control(d->dev.devt, d);

	ret = device_add(&d->dev);

	if (parent)
		mutex_unlock(&parent->lock);

	if (ret < 0) {
		kdbus_domain_disconnect(d);
		kdbus_domain_unref(d);
		return ERR_PTR(ret);
	}

	return d;

exit_put:
	put_device(&d->dev);
	return ERR_PTR(ret);
}

/**
 * kdbus_domain_user_assign_id() - allocate ID and assign it to the
 *				   domain user
 * @domain:		The domain of the user
 * @user:		The kdbus_domain_user object of the user
 *
 * Returns 0 if ID in [0, INT_MAX] is successfully assigned to the
 * domain user. Negative errno on failure.
 *
 * The user index is used in arrays for accounting user quota in
 * receiver queues.
 *
 * Caller must have the domain lock held and must ensure that the
 * domain was not disconnected.
 */
static int kdbus_domain_user_assign_id(struct kdbus_domain *domain,
				       struct kdbus_domain_user *user)
{
	int ret;

	/*
	 * Allocate the smallest possible index for this user; used
	 * in arrays for accounting user quota in receiver queues.
	 */
	ret = idr_alloc(&domain->user_idr, user, 0, 0, GFP_KERNEL);
	if (ret < 0)
		return ret;

	user->idr = ret;

	return 0;
}

/**
 * kdbus_domain_get_user_unlocked() - get a kdbus_domain_user object
 * @domain:		The domain of the user
 * @uid:		The uid of the user; INVALID_UID for an
 *			anonymous user like a custom endpoint
 * @user:		Pointer to a reference where the accounted
 *			domain user will be stored.
 *
 * Return: 0 on success, negative errno on failure.
 *
 * If there is a uid matching, then use the already accounted
 * kdbus_domain_user, increment its reference counter and
 * return it in the @user argument. Otherwise allocate a new one,
 * link it into the domain and return it.
 */
int kdbus_domain_get_user_unlocked(struct kdbus_domain *domain,
				   kuid_t uid,
				   struct kdbus_domain_user **user)
{
	int ret;
	struct kdbus_domain_user *tmp_user;
	struct kdbus_domain_user *u = NULL;

	BUG_ON(!mutex_is_locked(&domain->lock));

	/* find uid and reference it */
	if (uid_valid(uid)) {
		hash_for_each_possible(domain->user_hash, tmp_user,
				       hentry, __kuid_val(uid)) {
			if (!uid_eq(tmp_user->uid, uid))
				continue;

			/*
			 * If the ref-count is already 0, the destructor is
			 * about to unlink and destroy the object. Continue
			 * looking for a next one or create one, if none found.
			 */
			if (kref_get_unless_zero(&tmp_user->kref)) {
				u = tmp_user;
				goto out;
			}
		}
	}

	ret = -ENOMEM;
	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return ret;

	kref_init(&u->kref);
	u->domain = kdbus_domain_ref(domain);
	u->uid = uid;
	atomic_set(&u->buses, 0);
	atomic_set(&u->connections, 0);

	/* Assign user ID and link into domain */
	ret = kdbus_domain_user_assign_id(domain, u);
	if (ret < 0)
		goto exit_free;

	/* UID hash map */
	hash_add(domain->user_hash, &u->hentry, __kuid_val(u->uid));

out:
	*user = u;
	return 0;

exit_free:
	kdbus_domain_unref(u->domain);
	kfree(u);
	return ret;
}

/**
 * kdbus_domain_get_user() - get a kdbus_domain_user object
 * @domain:		The domain of the user
 * @uid:		The uid of the user; INVALID_UID for an
 *			anonymous user like a custom endpoint
 * @user:		Pointer to a reference where the accounted
 *			domain user will be stored.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_domain_get_user(struct kdbus_domain *domain,
			  kuid_t uid,
			  struct kdbus_domain_user **user)
{
	int ret = -ESHUTDOWN;

	mutex_lock(&domain->lock);
	if (!domain->disconnected)
		ret = kdbus_domain_get_user_unlocked(domain, uid, user);
	mutex_unlock(&domain->lock);

	return ret;
}

static void __kdbus_domain_user_free(struct kref *kref)
{
	struct kdbus_domain_user *user =
		container_of(kref, struct kdbus_domain_user, kref);

	BUG_ON(atomic_read(&user->buses) > 0);
	BUG_ON(atomic_read(&user->connections) > 0);

	/*
	 * Lookups ignore objects with a ref-count of 0. Therefore, we can
	 * safely remove it from the table after dropping the last reference.
	 * No-one will acquire a ref in parallel.
	 */
	mutex_lock(&user->domain->lock);
	idr_remove(&user->domain->user_idr, user->idr);
	hash_del(&user->hentry);
	mutex_unlock(&user->domain->lock);

	kdbus_domain_unref(user->domain);
	kfree(user);
}

/**
 * kdbus_domain_user_ref() - take a domain user reference
 * @u:		User
 *
 * Return: the domain user itself
 */
struct kdbus_domain_user *kdbus_domain_user_ref(struct kdbus_domain_user *u)
{
	kref_get(&u->kref);
	return u;
}

/**
 * kdbus_domain_user_unref() - drop a domain user eference
 * @u:		User
 *
 * When the last reference is dropped, the domain internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_domain_user *kdbus_domain_user_unref(struct kdbus_domain_user *u)
{
	if (u)
		kref_put(&u->kref, __kdbus_domain_user_free);
	return NULL;
}
