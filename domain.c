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
	struct kdbus_domain *domain = container_of(node, struct kdbus_domain,
						   node);

	BUG_ON(!hash_empty(domain->user_hash));

	put_pid_ns(domain->pid_namespace);
	put_user_ns(domain->user_namespace);
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

	d->access = access;
	mutex_init(&d->lock);
	atomic64_set(&d->msg_seq_last, 0);
	idr_init(&d->user_idr);
	d->pid_namespace = get_pid_ns(task_active_pid_ns(current));
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
	struct kdbus_node *control;

	/*
	 * kdbus_domain_activate() must not be called multiple times, so if
	 * kdbus_node_activate() didn't activate the node, it must already be
	 * dead.
	 */
	if (!kdbus_node_activate(&domain->node))
		return -ESHUTDOWN;

	/*
	 * Create a control-node for this domain. We drop our own reference
	 * immediately, effectively causing the node to be deactivated and
	 * released when the parent domain is.
	 */
	control = kdbus_domain_control_new(domain, domain->access);
	if (IS_ERR(control))
		return PTR_ERR(control);

	kdbus_node_activate(control);
	kdbus_node_unref(control);

	return 0;
}

/**
 * kdbus_domain_deactivate() - invalidate a domain
 * @domain:		Domain
 */
void kdbus_domain_deactivate(struct kdbus_domain *domain)
{
	kdbus_node_deactivate(&domain->node);
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
 * kdbus_domain_get_user() - get a kdbus_domain_user object
 * @domain:		The domain of the user
 * @uid:		The uid of the user; INVALID_UID for an
 *			anonymous user like a custom endpoint
 *
 * If there is a uid matching, then use the already accounted
 * kdbus_domain_user, increment its reference counter and return it.
 * Otherwise allocate a new one, link it into the domain and return it.
 *
 * Return: the accounted domain user on success, ERR_PTR on failure.
 */
struct kdbus_domain_user *kdbus_domain_get_user(struct kdbus_domain *domain,
						kuid_t uid)
{
	int ret;
	struct kdbus_domain_user *tmp_user;
	struct kdbus_domain_user *u = NULL;

	mutex_lock(&domain->lock);

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
				mutex_unlock(&domain->lock);
				return tmp_user;
			}
		}
	}

	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

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

	mutex_unlock(&domain->lock);
	return u;

exit_free:
	kdbus_domain_unref(u->domain);
	kfree(u);
exit_unlock:
	mutex_unlock(&domain->lock);
	return ERR_PTR(ret);
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
	if (u)
		kref_put(&u->kref, __kdbus_domain_user_free);
	return NULL;
}
