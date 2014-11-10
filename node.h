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

#ifndef __KDBUS_NODE_H
#define __KDBUS_NODE_H

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/wait.h>

struct kdbus_domain;
struct kdbus_bus;
struct kdbus_ep;

#define KDBUS_NODE_ACTIVE_BIAS (INT_MIN + 1)

enum kdbus_node_type {
	KDBUS_NODE_DOMAIN,
	KDBUS_NODE_BUS,
	KDBUS_NODE_ENDPOINT,
};

struct kdbus_node {
	struct kref ref;
	unsigned int id;
	unsigned int type;

	wait_queue_head_t waitq;
	atomic_t active;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif

	union {
		struct kdbus_domain *domain;
		struct kdbus_bus *bus;
		struct kdbus_ep *endpoint;
	};
};

void kdbus_node_init(void);
void kdbus_node_exit(void);

struct kdbus_node *kdbus_node_new_domain(struct kdbus_domain *domain);
struct kdbus_node *kdbus_node_new_bus(struct kdbus_bus *bus);
struct kdbus_node *kdbus_node_new_endpoint(struct kdbus_ep *endpoint);
struct kdbus_node *kdbus_node_ref(struct kdbus_node *node);
struct kdbus_node *kdbus_node_unref(struct kdbus_node *node);

bool kdbus_node_is_active(struct kdbus_node *node);
void kdbus_node_activate(struct kdbus_node *node);
void kdbus_node_deactivate(struct kdbus_node *node);
void kdbus_node_drain(struct kdbus_node *node);

bool kdbus_node_acquire(struct kdbus_node *node);
void kdbus_node_release(struct kdbus_node *node);

struct kdbus_node *kdbus_node_find_by_id(unsigned int id);

#endif
