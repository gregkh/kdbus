/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

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

static void kdbus_domain_control_free(struct kdbus_node *node)
{
	kfree(node);
}

static struct kdbus_node *kdbus_domain_control_new(struct kdbus_domain *domain,
						   unsigned int access)
{
	struct kdbus_node *node;
	int ret;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	kdbus_node_init(node, KDBUS_NODE_CONTROL);

	node->free_cb = kdbus_domain_control_free;
	node->mode = domain->node.mode;
	node->mode = S_IRUSR | S_IWUSR;
	if (access & (KDBUS_MAKE_ACCESS_GROUP | KDBUS_MAKE_ACCESS_WORLD))
		node->mode |= S_IRGRP | S_IWGRP;
	if (access & KDBUS_MAKE_ACCESS_WORLD)
		node->mode |= S_IROTH | S_IWOTH;

	ret = kdbus_node_link(node, &domain->node, "control");
	if (ret < 0)
		goto exit_free;

	return node;

exit_free:
	kdbus_node_deactivate(node);
	kdbus_node_unref(node);
	return ERR_PTR(ret);
}

static void kdbus_domain_free(struct kdbus_node *node)
{
	struct kdbus_domain *domain =
		container_of(node, struct kdbus_domain, node);

	put_user_ns(domain->user_namespace);
	ida_destroy(&domain->user_ida);
	idr_destroy(&domain->user_idr);
	kfree(domain);
}

/**
 * kdbus_domain_new() - create a new domain
 * @access:		The access mode for this node (KDBUS_MAKE_ACCESS_*)
 *
 * Return: a new kdbus_domain on success, ERR_PTR on failure
 */
struct kdbus_domain *kdbus_domain_new(unsigned int access)
{
	struct kdbus_domain *d;
	int ret;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return ERR_PTR(-ENOMEM);

	kdbus_node_init(&d->node, KDBUS_NODE_DOMAIN);

	d->node.free_cb = kdbus_domain_free;
	d->node.mode = S_IRUSR | S_IXUSR;
	if (access & (KDBUS_MAKE_ACCESS_GROUP | KDBUS_MAKE_ACCESS_WORLD))
		d->node.mode |= S_IRGRP | S_IXGRP;
	if (access & KDBUS_MAKE_ACCESS_WORLD)
		d->node.mode |= S_IROTH | S_IXOTH;

	mutex_init(&d->lock);
	idr_init(&d->user_idr);
	ida_init(&d->user_ida);

	/* Pin user namespace so we can guarantee domain-unique bus * names. */
	d->user_namespace = get_user_ns(current_user_ns());

	ret = kdbus_node_link(&d->node, NULL, NULL);
	if (ret < 0)
		goto exit_unref;

	return d;

exit_unref:
	kdbus_node_deactivate(&d->node);
	kdbus_node_unref(&d->node);
	return ERR_PTR(ret);
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
 * kdbus_domain_populate() - populate static domain nodes
 * @domain:	domain to populate
 * @access:	KDBUS_MAKE_ACCESS_* access restrictions for new nodes
 *
 * Allocate and activate static sub-nodes of the given domain. This will fail if
 * you call it on a non-active node or if the domain was already populated.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_domain_populate(struct kdbus_domain *domain, unsigned int access)
{
	struct kdbus_node *control;

	/*
	 * Create a control-node for this domain. We drop our own reference
	 * immediately, effectively causing the node to be deactivated and
	 * released when the parent domain is.
	 */
	control = kdbus_domain_control_new(domain, access);
	if (IS_ERR(control))
		return PTR_ERR(control);

	kdbus_node_activate(control);
	kdbus_node_unref(control);
	return 0;
}

/**
 * kdbus_user_lookup() - lookup a kdbus_user object
 * @domain:		domain of the user
 * @uid:		uid of the user; INVALID_UID for an anon user
 *
 * Lookup the kdbus user accounting object for the given domain. If INVALID_UID
 * is passed, a new anonymous user is created which is private to the caller.
 *
 * Return: The user object is returned, ERR_PTR on failure.
 */
struct kdbus_user *kdbus_user_lookup(struct kdbus_domain *domain, kuid_t uid)
{
	struct kdbus_user *u = NULL, *old = NULL;
	int ret;

	mutex_lock(&domain->lock);

	if (uid_valid(uid)) {
		old = idr_find(&domain->user_idr, __kuid_val(uid));
		/*
		 * If the object is about to be destroyed, ignore it and
		 * replace the slot in the IDR later on.
		 */
		if (old && kref_get_unless_zero(&old->kref)) {
			mutex_unlock(&domain->lock);
			return old;
		}
	}

	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u) {
		ret = -ENOMEM;
		goto exit;
	}

	kref_init(&u->kref);
	u->domain = kdbus_domain_ref(domain);
	u->uid = uid;
	atomic_set(&u->buses, 0);
	atomic_set(&u->connections, 0);

	if (uid_valid(uid)) {
		if (old) {
			idr_replace(&domain->user_idr, u, __kuid_val(uid));
			old->uid = INVALID_UID; /* mark old as removed */
		} else {
			ret = idr_alloc(&domain->user_idr, u, __kuid_val(uid),
					__kuid_val(uid) + 1, GFP_KERNEL);
			if (ret < 0)
				goto exit;
		}
	}

	/*
	 * Allocate the smallest possible index for this user; used
	 * in arrays for accounting user quota in receiver queues.
	 */
	ret = ida_simple_get(&domain->user_ida, 1, 0, GFP_KERNEL);
	if (ret < 0)
		goto exit;

	u->id = ret;
	mutex_unlock(&domain->lock);
	return u;

exit:
	if (u) {
		if (uid_valid(u->uid))
			idr_remove(&domain->user_idr, __kuid_val(u->uid));
		kdbus_domain_unref(u->domain);
		kfree(u);
	}
	mutex_unlock(&domain->lock);
	return ERR_PTR(ret);
}

static void __kdbus_user_free(struct kref *kref)
{
	struct kdbus_user *user = container_of(kref, struct kdbus_user, kref);

	WARN_ON(atomic_read(&user->buses) > 0);
	WARN_ON(atomic_read(&user->connections) > 0);

	mutex_lock(&user->domain->lock);
	ida_simple_remove(&user->domain->user_ida, user->id);
	if (uid_valid(user->uid))
		idr_remove(&user->domain->user_idr, __kuid_val(user->uid));
	mutex_unlock(&user->domain->lock);

	kdbus_domain_unref(user->domain);
	kfree(user);
}

/**
 * kdbus_user_ref() - take a user reference
 * @u:		User
 *
 * Return: @u is returned
 */
struct kdbus_user *kdbus_user_ref(struct kdbus_user *u)
{
	if (u)
		kref_get(&u->kref);
	return u;
}

/**
 * kdbus_user_unref() - drop a user reference
 * @u:		User
 *
 * Return: NULL
 */
struct kdbus_user *kdbus_user_unref(struct kdbus_user *u)
{
	if (u)
		kref_put(&u->kref, __kdbus_user_free);
	return NULL;
}
