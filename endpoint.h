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

#ifndef __KDBUS_ENDPOINT_H
#define __KDBUS_ENDPOINT_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/uidgid.h>
#include "node.h"
#include "policy.h"

struct kdbus_bus;
struct kdbus_user;

/**
 * struct kdbus_ep - enpoint to access a bus
 * @node:		The kdbus node
 * @lock:		Endpoint data lock
 * @bus:		Bus behind this endpoint
 * @user:		Custom enpoints account against an anonymous user
 * @policy_db:		Uploaded policy
 * @conn_list:		Connections of this endpoint
 *
 * An enpoint offers access to a bus; the default endpoint node name is "bus".
 * Additional custom endpoints to the same bus can be created and they can
 * carry their own policies/filters.
 */
struct kdbus_ep {
	struct kdbus_node node;
	struct mutex lock;

	/* static */
	struct kdbus_bus *bus;
	struct kdbus_user *user;

	/* protected by own locks */
	struct kdbus_policy_db policy_db;

	/* protected by ep->lock */
	struct list_head conn_list;
};

#define kdbus_ep_from_node(_node) \
	container_of((_node), struct kdbus_ep, node)

struct kdbus_ep *kdbus_ep_new(struct kdbus_bus *bus, const char *name,
			      unsigned int access, kuid_t uid, kgid_t gid,
			      bool policy);
struct kdbus_ep *kdbus_ep_ref(struct kdbus_ep *ep);
struct kdbus_ep *kdbus_ep_unref(struct kdbus_ep *ep);

struct kdbus_ep *kdbus_cmd_ep_make(struct kdbus_bus *bus, void __user *argp);
int kdbus_cmd_ep_update(struct kdbus_ep *ep, void __user *argp);

#endif
