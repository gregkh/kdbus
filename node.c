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
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kdev_t.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "bus.h"
#include "domain.h"
#include "endpoint.h"
#include "handle.h"
#include "node.h"

#define KDBUS_NODE_ACTIVE_BIAS		(INT_MIN + 3)
#define KDBUS_NODE_ACTIVE_RELEASE	(KDBUS_NODE_ACTIVE_BIAS - 1)
#define KDBUS_NODE_ACTIVE_DRAINED	(KDBUS_NODE_ACTIVE_BIAS - 2)
#define KDBUS_NODE_ACTIVE_NEW		(KDBUS_NODE_ACTIVE_BIAS - 3)

/* IDs may be used as minor-numbers, so limit it to the highest minor */
#define KDBUS_NODE_IDR_MAX MINORMASK

/* global unique ID mapping for kdbus nodes */
static DEFINE_IDR(kdbus_node_idr);
static DECLARE_RWSEM(kdbus_node_idr_lock);

/* kdbus major */
unsigned int kdbus_major;

int kdbus_init_nodes(void)
{
	int ret;

	idr_init(&kdbus_node_idr);

	ret = __register_chrdev(0, 0, KDBUS_NODE_IDR_MAX + 1, KBUILD_MODNAME,
				&kdbus_handle_ops);
	if (ret < 0)
		goto exit_idr;

	kdbus_major = ret;

	return 0;

exit_idr:
	idr_destroy(&kdbus_node_idr);
	return ret;
}

void kdbus_exit_nodes(void)
{
	__unregister_chrdev(kdbus_major, 0, KDBUS_NODE_IDR_MAX + 1,
			    KBUILD_MODNAME);
	idr_destroy(&kdbus_node_idr);
}

int kdbus_node_init(struct kdbus_node *node, unsigned int type,
		    kdbus_node_free_t free_cb, kdbus_node_release_t release_cb)
{
	int ret;

	atomic_set(&node->refcnt, 1);
	mutex_init(&node->lock);
	node->id = 0;
	node->type = type;
	node->release_cb = release_cb;
	node->free_cb = free_cb;
	init_waitqueue_head(&node->waitq);
	atomic_set(&node->active, KDBUS_NODE_ACTIVE_NEW);

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

struct kdbus_node *kdbus_node_unref(struct kdbus_node *node)
{
	if (node && atomic_dec_and_test(&node->refcnt)) {
		down_write(&kdbus_node_idr_lock);
		if (node->id > 0)
			idr_remove(&kdbus_node_idr, node->id);
		up_write(&kdbus_node_idr_lock);

		if (node->free_cb)
			node->free_cb(node);
	}

	return NULL;
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

void kdbus_node_deactivate(struct kdbus_node *node)
{
	int v;

	mutex_lock(&node->lock);
	v = atomic_read(&node->active);
	if (v >= 0)
		v = atomic_add_return(KDBUS_NODE_ACTIVE_BIAS, &node->active);
	else if (v == KDBUS_NODE_ACTIVE_NEW)
		v = atomic_add_return(3, &node->active);
	else
		v = 0;
	mutex_unlock(&node->lock);

	if (v == KDBUS_NODE_ACTIVE_BIAS)
		wake_up(&node->waitq);
}

void kdbus_node_drain(struct kdbus_node *node)
{
	int v;

	wait_event(node->waitq,
		   atomic_read(&node->active) <= KDBUS_NODE_ACTIVE_BIAS);

	mutex_lock(&node->lock);
	v = atomic_read(&node->active);
	if (v == KDBUS_NODE_ACTIVE_BIAS)
		atomic_dec(&node->active);
	mutex_unlock(&node->lock);

	if (v == KDBUS_NODE_ACTIVE_BIAS) {
		if (node->release_cb)
			node->release_cb(node);

		atomic_dec(&node->active);
		wake_up_all(&node->waitq);
	}

	wait_event(node->waitq,
		   atomic_read(&node->active) == KDBUS_NODE_ACTIVE_DRAINED);
}

bool kdbus_node_acquire(struct kdbus_node *node)
{
	return node && atomic_inc_unless_negative(&node->active);
}

void kdbus_node_release(struct kdbus_node *node)
{
	if (node && atomic_dec_return(&node->active) == KDBUS_NODE_ACTIVE_BIAS)
		wake_up(&node->waitq);
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
