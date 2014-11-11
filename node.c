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
#include <linux/lockdep.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "bus.h"
#include "domain.h"
#include "endpoint.h"
#include "node.h"

#define KDBUS_NODE_ACTIVE_BIAS		(INT_MIN + 2)
#define KDBUS_NODE_ACTIVE_NEW		(KDBUS_NODE_ACTIVE_BIAS - 2)
#define KDBUS_NODE_ACTIVE_DRAINED	(KDBUS_NODE_ACTIVE_BIAS - 1)

/* IDs may be used as minor-numbers, so limit it to the highest minor */
#define KDBUS_NODE_IDR_MAX MINORMASK

/* global unique ID mapping for kdbus nodes */
static DEFINE_IDR(kdbus_node_idr);
static DECLARE_RWSEM(kdbus_node_idr_lock);

void kdbus_init_nodes(void)
{
	idr_init(&kdbus_node_idr);
}

void kdbus_exit_nodes(void)
{
	idr_destroy(&kdbus_node_idr);
}

int kdbus_node_init(struct kdbus_node *node, unsigned int type)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	static struct lock_class_key __key;
#endif
	int ret;

	atomic_set(&node->refcnt, 1);
	mutex_init(&node->lock);
	node->id = 0;
	node->type = type;
	init_waitqueue_head(&node->waitq);
	atomic_set(&node->active, KDBUS_NODE_ACTIVE_NEW);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	lockdep_init_map(&node->dep_map, "active", &__key, 0);
#endif

	down_write(&kdbus_node_idr_lock);
	ret = idr_alloc(&kdbus_node_idr, node, 1, KDBUS_NODE_IDR_MAX + 1,
			GFP_KERNEL);
	if (ret >= 0)
		node->id = ret;
	up_write(&kdbus_node_idr_lock);

	if (ret < 0)
		return ret;

	return 0;
}

struct kdbus_node *kdbus_node_ref(struct kdbus_node *node)
{
	if (node)
		atomic_inc(&node->refcnt);
	return node;
}

struct kdbus_node *kdbus_node_unref(struct kdbus_node *node,
				    kdbus_node_free_t free_cb)
{
	if (node && atomic_dec_and_test(&node->refcnt)) {
		down_write(&kdbus_node_idr_lock);
		idr_remove(&kdbus_node_idr, node->id);
		up_write(&kdbus_node_idr_lock);

		if (free_cb)
			free_cb(node);
	}

	return NULL;
}

static void kdbus_node_dropped(struct kdbus_node *node,
			       kdbus_node_release_t release)
{
	if (release)
		release(node);

	atomic_set(&node->active, KDBUS_NODE_ACTIVE_DRAINED);
	wake_up_all(&node->waitq);
}

bool kdbus_node_is_active(struct kdbus_node *node)
{
	return atomic_read(&node->active) >= 0;
}

void kdbus_node_activate(struct kdbus_node *node)
{
	mutex_lock(&node->lock);
	if (atomic_read(&node->active) == KDBUS_NODE_ACTIVE_NEW)
		atomic_sub(KDBUS_NODE_ACTIVE_NEW, &node->active);
	mutex_unlock(&node->lock);
}

void kdbus_node_deactivate(struct kdbus_node *node,
			   kdbus_node_release_t release)
{
	int v;

	mutex_lock(&node->lock);
	v = atomic_read(&node->active);
	if (v >= 0)
		v = atomic_add_return(KDBUS_NODE_ACTIVE_BIAS, &node->active);
	else if (v == KDBUS_NODE_ACTIVE_NEW)
		v = atomic_add_return(2, &node->active);
	else
		v = 0;
	mutex_unlock(&node->lock);

	if (v == KDBUS_NODE_ACTIVE_BIAS)
		kdbus_node_dropped(node, release);
}

void kdbus_node_drain(struct kdbus_node *node)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire(&node->dep_map, 0, 0, _RET_IP_);
	if (atomic_read(&node->active) != KDBUS_NODE_ACTIVE_BIAS)
		lock_contended(&node->dep_map, _RET_IP_);
#endif

	wait_event(node->waitq,
		   atomic_read(&node->active) == KDBUS_NODE_ACTIVE_DRAINED);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	lock_acquired(&node->dep_map, _RET_IP_);
	rwsem_release(&node->dep_map, 1, _RET_IP_);
#endif
}

bool kdbus_node_acquire(struct kdbus_node *node)
{
	if (!node || !atomic_inc_unless_negative(&node->active))
		return false;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_acquire_read(&node->dep_map, 0, 1, _RET_IP_);
#endif

	return true;
}

void kdbus_node_release(struct kdbus_node *node, kdbus_node_release_t release)
{
	if (!node)
		return;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	rwsem_release(&node->dep_map, 1, _RET_IP_);
#endif

	if (atomic_dec_return(&node->active) == KDBUS_NODE_ACTIVE_BIAS)
		kdbus_node_dropped(node, release);
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
