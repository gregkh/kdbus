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

#include <linux/atomic.h>
#include <linux/idr.h>
#include <linux/kdev_t.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "bus.h"
#include "domain.h"
#include "endpoint.h"
#include "node.h"

/* IDs may be used as minor-numbers, so limit it to the highest minor */
#define KDBUS_NODE_IDR_MAX MINORMASK

/* global unique ID mapping for kdbus nodes */
static DEFINE_IDR(kdbus_node_idr);
static DECLARE_RWSEM(kdbus_node_idr_lock);

void kdbus_node_init(void)
{
	idr_init(&kdbus_node_idr);
}

void kdbus_node_exit(void)
{
	idr_destroy(&kdbus_node_idr);
}

static struct kdbus_node *kdbus_node_new(void)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	static struct lock_class_key __key;
#endif
	struct kdbus_node *node;
	int ret;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	kref_init(&node->ref);
	init_waitqueue_head(&node->waitq);
	atomic_set(&node->active, KDBUS_NODE_ACTIVE_BIAS);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	lockdep_init_map(&node->dep_map, "active", &__key, 0);
#endif

	down_write(&kdbus_node_idr_lock);
	ret = idr_alloc(&kdbus_node_idr, node, 0, KDBUS_NODE_IDR_MAX + 1,
			GFP_KERNEL);
	up_write(&kdbus_node_idr_lock);

	if (ret < 0)
		goto exit_node;

	node->id = ret;

	return node;

exit_node:
	kfree(node);
	return ERR_PTR(ret);
}

struct kdbus_node *kdbus_node_new_domain(struct kdbus_domain *domain)
{
	struct kdbus_node *node;

	node = kdbus_node_new();
	if (!IS_ERR(node)) {
		node->type = KDBUS_NODE_DOMAIN;
		node->domain = domain;
	}

	return node;
}

struct kdbus_node *kdbus_node_new_bus(struct kdbus_bus *bus)
{
	struct kdbus_node *node;

	node = kdbus_node_new();
	if (!IS_ERR(node)) {
		node->type = KDBUS_NODE_BUS;
		node->bus = bus;
	}

	return node;
}

struct kdbus_node *kdbus_node_new_endpoint(struct kdbus_ep *endpoint)
{
	struct kdbus_node *node;

	node = kdbus_node_new();
	if (!IS_ERR(node)) {
		node->type = KDBUS_NODE_ENDPOINT;
		node->endpoint = endpoint;
	}

	return node;
}

static void kdbus_node_free(struct kref *ref)
{
	struct kdbus_node *node = container_of(ref, struct kdbus_node, ref);

	down_write(&kdbus_node_idr_lock);
	idr_remove(&kdbus_node_idr, node->id);
	up_write(&kdbus_node_idr_lock);

	kfree(node);
}

struct kdbus_node *kdbus_node_ref(struct kdbus_node *node)
{
	if (node)
		kref_get(&node->ref);
	return node;
}

struct kdbus_node *kdbus_node_unref(struct kdbus_node *node)
{
	if (node)
		kref_put(&node->ref, kdbus_node_free);
	return NULL;
}

bool kdbus_node_is_active(struct kdbus_node *node)
{
	return atomic_read(&node->active) >= 0;
}

void kdbus_node_activate(struct kdbus_node *node)
{
	atomic_sub(KDBUS_NODE_ACTIVE_BIAS, &node->active);
}

void kdbus_node_deactivate(struct kdbus_node *node)
{
	atomic_add(KDBUS_NODE_ACTIVE_BIAS, &node->active);
}

void kdbus_node_drain(struct kdbus_node *node)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire(&node->dep_map, 0, 0, _RET_IP_);
	if (atomic_read(&node->active) != KDBUS_NODE_ACTIVE_BIAS)
		lock_contended(&node->dep_map, _RET_IP_);
#endif

	wait_event(node->waitq,
		   atomic_read(&node->active) == KDBUS_NODE_ACTIVE_BIAS);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	lock_acquired(&node->dep_map, _RET_IP_);
	rwsem_release(&node->dep_map, 1, _RET_IP_);
#endif
}

bool kdbus_node_acquire(struct kdbus_node *node)
{
	if (!atomic_inc_unless_negative(&node->active))
		return false;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire_read(&node->dep_map, 0, 1, _RET_IP_);
#endif

	return true;
}

void kdbus_node_release(struct kdbus_node *node)
{
	int v;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_release(&node->dep_map, 1, _RET_IP_);
#endif

	v = atomic_dec_return(&node->active);
	if (v != KDBUS_NODE_ACTIVE_BIAS)
		return;

	wake_up_all(&node->waitq);
}

struct kdbus_node *kdbus_node_find_by_id(unsigned int id)
{
	struct kdbus_node *node;

	down_read(&kdbus_node_idr_lock);
	node = idr_find(&kdbus_node_idr, id);
	if (node && kdbus_node_acquire(node))
		kdbus_node_ref(node);
	else
		node = NULL;
	up_read(&kdbus_node_idr_lock);

	return node;
}
