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

static void kdbus_domain_free(struct kdbus_node *node);
static void kdbus_domain_release(struct kdbus_node *node);

/* control nodes are world accessible */
static char *kdbus_domain_dev_devnode(struct device *dev, umode_t *mode,
				      kuid_t *uid, kgid_t *gid)
{
	struct kdbus_domain *domain = dev_get_drvdata(dev);

	if (mode)
		*mode = domain->control->mode;

	return NULL;
}

static void kdbus_domain_dev_release(struct device *dev)
{
	kfree(dev);
}

static struct device_type kdbus_domain_dev_type = {
	.name		= "control",
	.devnode	= kdbus_domain_dev_devnode,
	.release	= kdbus_domain_dev_release,
};

static void kdbus_domain_control_free(struct kdbus_node *node)
{
	kfree(node);
}

static struct kdbus_node *kdbus_domain_control_new(struct kdbus_domain *domain)
{
	struct kdbus_node *node;
	int ret;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	ret = kdbus_node_init(node, &domain->node,
			      KDBUS_NODE_CONTROL, "control",
			      kdbus_domain_control_free, NULL);
	if (ret < 0)
		goto exit_free;

	node->mode = domain->node.mode;

	return node;

exit_free:
	kfree(node);
	return ERR_PTR(ret);
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

	INIT_LIST_HEAD(&d->bus_list);
	INIT_LIST_HEAD(&d->domain_list);
	d->parent = kdbus_domain_ref(parent);
	mutex_init(&d->lock);
	atomic64_set(&d->msg_seq_last, 0);
	idr_init(&d->user_idr);

	ret = kdbus_node_init(&d->node,
			      parent ? &parent->node : NULL,
			      KDBUS_NODE_DOMAIN, name,
			      kdbus_domain_free, kdbus_domain_release);
	if (ret < 0)
		goto exit_unref;

	d->node.mode = 0755;

	/* compose name and path of base directory in /dev */
	if (parent) {
		d->devpath = kasprintf(GFP_KERNEL, "%s/domain/%s",
				       parent->devpath, name);
		if (!d->devpath) {
			ret = -ENOMEM;
			goto exit_unref;
		}
	} else {
		/* initial domain */
		d->devpath = kstrdup(KBUILD_MODNAME, GFP_KERNEL);
		if (!d->devpath) {
			ret = -ENOMEM;
			goto exit_unref;
		}
	}

	d->control = kdbus_domain_control_new(d);
	if (IS_ERR(d->control)) {
		ret = PTR_ERR(d->control);
		goto exit_unref;
	}

	d->dev = kzalloc(sizeof(*d->dev), GFP_KERNEL);
	if (!d->dev) {
		ret = -ENOMEM;
		goto exit_unref;
	}

	device_initialize(d->dev);
	dev_set_drvdata(d->dev, d);
	d->dev->bus = &kdbus_subsys;
	d->dev->type = &kdbus_domain_dev_type;
	d->dev->devt = MKDEV(kdbus_major, d->control->id);

	ret = dev_set_name(d->dev, "%s/control", d->devpath);
	if (ret < 0)
		goto exit_unref;

	d->control->mode = mode;

	d->id = atomic64_inc_return(&kdbus_domain_seq_last);

	return d;

exit_unref:
	kdbus_domain_unref(d);
	return ERR_PTR(ret);
}

static void kdbus_domain_free(struct kdbus_node *node)
{
	struct kdbus_domain *domain = container_of(node, struct kdbus_domain,
						   node);

	BUG_ON(kdbus_domain_is_active(domain));
	BUG_ON(!list_empty(&domain->domain_list));
	BUG_ON(!list_empty(&domain->bus_list));
	BUG_ON(!hash_empty(domain->user_hash));

	kdbus_node_unref(domain->control);
	kdbus_domain_unref(domain->parent);
	idr_destroy(&domain->user_idr);
	put_device(domain->dev);
	kfree(domain->devpath);
	kfree(domain);
}

/**
 * kdbus_domain_ref() - take a domain reference
 * @domain:		Domain
 *
 * Return: the domain itself
 */
struct kdbus_domain *kdbus_domain_ref(struct kdbus_domain *domain)
{
	if (domain)
		kdbus_node_ref(&domain->node);
	return domain;
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
		kdbus_node_unref(&domain->node);
	return NULL;
}

/**
 * kdbus_domain_activate() - activate a domain
 * @domain:		Domain
 *
 * Activate a domain so it will be visible to user-space and can be accessed
 * by external entities.
 *
 * Returns: 0 on success, negative error-code on failure
 */
int kdbus_domain_activate(struct kdbus_domain *domain)
{
	int ret;

	if (domain->parent) {
		/* lock order: parent domain -> domain */
		mutex_lock(&domain->parent->lock);

		if (!kdbus_domain_is_active(domain->parent)) {
			mutex_unlock(&domain->parent->lock);
			return -ESHUTDOWN;
		}

		list_add_tail(&domain->domain_entry,
			      &domain->parent->domain_list);
	}

	/*
	 * We have to mark the domain as enabled _before_ running device_add().
	 * Otherwise, there's a race between UEVENT_ADD (generated by
	 * device_add()) and us enabling the minor.
	 * However, this means user-space can open the minor before we called
	 * device_add(). This is fine, as we never require the device to be
	 * registered, anyway.
	 */

	kdbus_node_activate(&domain->node);
	kdbus_node_activate(domain->control);

	if (domain == kdbus_domain_init || domain->node.name)
		ret = device_add(domain->dev);
	else
		ret = 0;

	if (domain->parent)
		mutex_unlock(&domain->parent->lock);

	if (ret < 0)
		goto exit_unregister;

	return 0;

exit_unregister:
	kdbus_domain_deactivate(domain);
	return ret;
}

static void kdbus_domain_release(struct kdbus_node *node)
{
	struct kdbus_domain *domain = container_of(node, struct kdbus_domain,
						   node);

	/* disconnect from parent domain */
	if (domain->parent) {
		mutex_lock(&domain->parent->lock);
		list_del(&domain->domain_entry);
		mutex_unlock(&domain->parent->lock);
	}

	if (device_is_registered(domain->dev))
		device_del(domain->dev);

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

		kdbus_domain_deactivate(dom);
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

		kdbus_bus_deactivate(bus);
		kdbus_bus_unref(bus);
	}
}

/**
 * kdbus_domain_deactivate() - invalidate a domain
 * @domain:		Domain
 */
void kdbus_domain_deactivate(struct kdbus_domain *domain)
{
	kdbus_node_deactivate(domain->control);
	kdbus_node_deactivate(&domain->node);
	kdbus_node_drain(domain->control);
	kdbus_node_drain(&domain->node);
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
 *
 * Return: accounted domain user on success, ERR_PTR on failure.
 *
 * If there is a uid matching, then use the already accounted
 * kdbus_domain_user, increment its reference counter and return it.
 * Otherwise allocate a new one, * link it into the domain and return it.
 */
struct kdbus_domain_user *
kdbus_domain_get_user_unlocked(struct kdbus_domain *domain, kuid_t uid)
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
			if (kref_get_unless_zero(&tmp_user->kref))
				return tmp_user;
		}
	}

	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return ERR_PTR(-ENOMEM);

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

	return u;

exit_free:
	kdbus_domain_unref(u->domain);
	kfree(u);
	return ERR_PTR(ret);
}

/**
 * kdbus_domain_get_user() - get a kdbus_domain_user object
 * @domain:		The domain of the user
 * @uid:		The uid of the user; INVALID_UID for an
 *			anonymous user like a custom endpoint
 *
 * Return: the accounted domain user on success, ERR_PTR on failure.
 */
struct kdbus_domain_user *
kdbus_domain_get_user(struct kdbus_domain *domain, kuid_t uid)
{
	struct kdbus_domain_user *u;

	mutex_lock(&domain->lock);
	u = kdbus_domain_get_user_unlocked(domain, uid);
	mutex_unlock(&domain->lock);

	return u;
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
 * kdbus_domain_user_unref() - drop a domain user reference
 * @u:		User
 *
 * When the last reference is dropped, the domain internal structure
 * is freed.
 *
 * Return: NULL
 */
struct kdbus_domain_user *kdbus_domain_user_unref(struct kdbus_domain_user *u)
{
	if (!IS_ERR_OR_NULL(u))
		kref_put(&u->kref, __kdbus_domain_user_free);
	return NULL;
}
