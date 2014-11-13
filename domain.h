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

#ifndef __KDBUS_DOMAIN_H
#define __KDBUS_DOMAIN_H

#include <linux/device.h>
#include <linux/hashtable.h>
#include <linux/idr.h>

#include "node.h"

/**
 * struct kdbus_domain - domain for buses
 * @node:		Underlying API node
 * @dev:		Sysfs device
 * @devpath:		/dev base directory path
 * @parent:		Parent domain
 * @control:		Control device node
 * @id:			Global id of this domain
 * @lock:		Domain data lock
 * @bus_seq_last:	Last used bus id sequence number
 * @msg_seq_last:	Last used message id sequence number
 * @domain_list:	List of child domains
 * @domain_entry:	Entry in parent domain
 * @bus_list:		Buses in this domain
 * @user_hash:		Accounting of user resources
 * @user_idr:		Map of all users; smallest possible index
 *
 * A domain provides a "control" device node. Every domain has its
 * own major number for its endpoint device nodes.
 *
 * The initial domain is created at initialization time, is unnamed and
 * stays around for forver.
 *
 * A domain is created by opening the "control" device node of the
 * parent domain and issuing the KDBUS_CMD_DOMAIN_MAKE iotcl. Closing this
 * file immediately destroys the entire domain.
 */
struct kdbus_domain {
	struct kdbus_node node;
	struct device *dev;
	const char *devpath;
	struct kdbus_domain *parent;
	struct kdbus_node *control;
	u64 id;
	struct mutex lock;
	atomic64_t bus_seq_last;
	atomic64_t msg_seq_last;
	struct list_head domain_list;
	struct list_head domain_entry;
	struct list_head bus_list;
	DECLARE_HASHTABLE(user_hash, 6);
	struct idr user_idr;
};

/**
 * struct kdbus_domain_user - resource accounting for users
 * @kref:		Reference counter
 * @domain:		Domain of the user
 * @hentry:		Entry in domain user map
 * @idr:		Smallest possible index number of all users
 * @uid:		UID of the user
 * @buses:		Number of buses the user has created
 * @connections:	Number of connections the user has created
 */
struct kdbus_domain_user {
	struct kref kref;
	struct kdbus_domain *domain;
	struct hlist_node hentry;
	unsigned int idr;
	kuid_t uid;
	atomic_t buses;
	atomic_t connections;
};

extern struct bus_type kdbus_subsys;
extern struct kdbus_domain *kdbus_domain_init;

#define kdbus_domain_from_node(_node) container_of((_node), \
						   struct kdbus_domain, \
						   node)

struct kdbus_domain *kdbus_domain_new(struct kdbus_domain *parent,
				      const char *name, unsigned int access);
struct kdbus_domain *kdbus_domain_ref(struct kdbus_domain *domain);
struct kdbus_domain *kdbus_domain_unref(struct kdbus_domain *domain);
int kdbus_domain_activate(struct kdbus_domain *domain);
void kdbus_domain_deactivate(struct kdbus_domain *domain);

static inline bool kdbus_domain_is_active(struct kdbus_domain *domain)
{
	return kdbus_node_is_active(&domain->node);
}

struct kdbus_domain_user *
kdbus_domain_get_user_unlocked(struct kdbus_domain *domain, kuid_t uid);
struct kdbus_domain_user *
kdbus_domain_get_user(struct kdbus_domain *domain, kuid_t uid);

struct kdbus_domain_user *kdbus_domain_user_ref(struct kdbus_domain_user *u);
struct kdbus_domain_user *kdbus_domain_user_unref(struct kdbus_domain_user *u);

#endif
