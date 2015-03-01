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

#ifndef __KDBUS_DOMAIN_H
#define __KDBUS_DOMAIN_H

#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/user_namespace.h>

#include "node.h"

/**
 * struct kdbus_domain - domain for buses
 * @node:		Underlying API node
 * @lock:		Domain data lock
 * @last_id:		Last used object id
 * @user_idr:		Set of all users indexed by UID
 * @user_ida:		Set of all users to compute small indices
 * @user_namespace:	User namespace, pinned at creation time
 * @dentry:		Root dentry of VFS mount (don't use outside of kdbusfs)
 */
struct kdbus_domain {
	struct kdbus_node node;
	struct mutex lock;
	atomic64_t last_id;
	struct idr user_idr;
	struct ida user_ida;
	struct user_namespace *user_namespace;
	struct dentry *dentry;
};

/**
 * struct kdbus_user - resource accounting for users
 * @kref:		Reference counter
 * @domain:		Domain of the user
 * @id:			Index of this user
 * @uid:		UID of the user
 * @buses:		Number of buses the user has created
 * @connections:	Number of connections the user has created
 */
struct kdbus_user {
	struct kref kref;
	struct kdbus_domain *domain;
	unsigned int id;
	kuid_t uid;
	atomic_t buses;
	atomic_t connections;
};

#define kdbus_domain_from_node(_node) \
	container_of((_node), struct kdbus_domain, node)

struct kdbus_domain *kdbus_domain_new(unsigned int access);
struct kdbus_domain *kdbus_domain_ref(struct kdbus_domain *domain);
struct kdbus_domain *kdbus_domain_unref(struct kdbus_domain *domain);
int kdbus_domain_populate(struct kdbus_domain *domain, unsigned int access);

#define KDBUS_USER_KERNEL_ID 0 /* ID 0 is reserved for kernel accounting */

struct kdbus_user *kdbus_user_lookup(struct kdbus_domain *domain, kuid_t uid);
struct kdbus_user *kdbus_user_ref(struct kdbus_user *u);
struct kdbus_user *kdbus_user_unref(struct kdbus_user *u);

#endif
