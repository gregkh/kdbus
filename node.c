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
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "bus.h"
#include "domain.h"
#include "endpoint.h"
#include "handle.h"
#include "node.h"
#include "util.h"

#define KDBUS_NODE_BIAS		(INT_MIN + 3)
#define KDBUS_NODE_RELEASE	(KDBUS_NODE_BIAS - 1)
#define KDBUS_NODE_DRAINED	(KDBUS_NODE_BIAS - 2)
#define KDBUS_NODE_NEW		(KDBUS_NODE_BIAS - 3)

/* IDs may be used as minor-numbers, so limit it to the highest minor */
#define KDBUS_NODE_IDR_MAX MINORMASK

/* global unique ID mapping for kdbus nodes */
static DEFINE_IDR(kdbus_node_idr);
static DECLARE_RWSEM(kdbus_node_idr_lock);

/**
 * kdbus_node_name_hash() - hash a name
 * @name:	The string to hash
 *
 * Return: the hash of @name, guaranteed to be in the range [2..INT_MAX+2].
 * The values 1 and 2 are unused as they are reserved for the filesystem code,
 * so it can accommodate the '.' and '..' directory entries.
 */
unsigned int kdbus_node_name_hash(const char *name)
{
	unsigned int hash;

	hash = kdbus_str_hash(name);

	/* Reserve hash numbers 0, 1 and INT_MAX for magic directory entries */
	if (hash >= INT_MAX)
		hash = (hash & INT_MAX) - 1;

	if (hash < 2)
		hash += 2;

	return hash;
}

/**
 * kdbus_node_name_compare() - compare a name with a node's name
 * @hash:	The hash of the string to compare the node with
 * @name:	The name to compare the node with
 * @node:	The node to compare the name with
 *
 * Return: 0 if @name and @hash exactly match the information in @node, or
 * an integer less than or greater than zero if @name is found, respectively,
 * to be less than or be greater than the string stored in @node.
 */
int kdbus_node_name_compare(unsigned int hash, const char *name,
			    const struct kdbus_node *node)
{
	if (hash != node->hash)
		return hash - node->hash;

	return strcmp(name, node->name);
}

static int kdbus_node_compare(const struct kdbus_node *left,
			      const struct kdbus_node *right)
{
	return kdbus_node_name_compare(left->hash, left->name, right);
}

/**
 * kdbus_node_init() - initialize a kdbus_node
 * @node:	Pointer to the node to initialize
 * @type:	The type the node will have (KDBUS_NODE_*)
 * @free_cb:	A callback to call when the node is freed
 * @release_cb:	A callback to call when the node is released
 */
void kdbus_node_init(struct kdbus_node *node, unsigned int type,
		     kdbus_node_free_t free_cb, kdbus_node_release_t release_cb)
{
	atomic_set(&node->refcnt, 1);
	mutex_init(&node->lock);
	node->id = 0;
	node->type = type;
	RB_CLEAR_NODE(&node->rb);
	node->children = RB_ROOT;
	node->release_cb = release_cb;
	node->free_cb = free_cb;
	init_waitqueue_head(&node->waitq);
	atomic_set(&node->active, KDBUS_NODE_NEW);
}

/**
 * kdbus_node_init() - link a node into the nodes system
 * @node:	Pointer to the node to initialize
 * @parent:	Pointer to a parent node, may be %NULL
 * @name:	The name the node should represent
 *
 * Return: 0 on success. negative error otherwise.
 */
int kdbus_node_link(struct kdbus_node *node, struct kdbus_node *parent,
		    const char *name)
{
	int ret;

	BUG_ON(node->type != KDBUS_NODE_DOMAIN && !parent);
	BUG_ON(parent && !name);

	if (name) {
		node->name = kstrdup(name, GFP_KERNEL);
		if (!node->name)
			return -ENOMEM;

		node->hash = kdbus_node_name_hash(name);
	}

	down_write(&kdbus_node_idr_lock);
	ret = idr_alloc(&kdbus_node_idr, node, 1, KDBUS_NODE_IDR_MAX + 1,
			GFP_KERNEL);
	if (ret >= 0)
		node->id = ret;
	up_write(&kdbus_node_idr_lock);

	if (ret < 0)
		return ret;

	ret = 0;

	if (parent) {
		struct rb_node **n, *prev;

		mutex_lock(&parent->lock);

		n = &parent->children.rb_node;
		prev = NULL;

		while (*n) {
			struct kdbus_node *pos;
			int result;

			pos = kdbus_node_from_rb(*n);
			prev = *n;
			result = kdbus_node_compare(node, pos);
			if (result == 0) {
				ret = -EEXIST;
				goto exit_unlock;
			}

			if (result < 0)
				n = &pos->rb.rb_left;
			else
				n = &pos->rb.rb_right;
		}

		/* add new node and rebalance the tree */
		rb_link_node(&node->rb, prev, n);
		rb_insert_color(&node->rb, &parent->children);
		node->parent = kdbus_node_ref(parent);

exit_unlock:
		mutex_unlock(&parent->lock);
	}

	return ret;
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
		struct kdbus_node safe = *node;

		if (node->parent) {
			mutex_lock(&node->parent->lock);
			if (!RB_EMPTY_NODE(&node->rb)) {
				rb_erase(&node->rb, &node->parent->children);
				RB_CLEAR_NODE(&node->rb);
			}
			mutex_unlock(&node->parent->lock);
		}

		if (node->free_cb)
			node->free_cb(node);

		down_write(&kdbus_node_idr_lock);
		if (safe.id > 0)
			idr_remove(&kdbus_node_idr, safe.id);
		/* drop caches after last node to not leak memory on unload */
		if (idr_is_empty(&kdbus_node_idr)) {
			idr_destroy(&kdbus_node_idr);
			idr_init(&kdbus_node_idr);
		}
		up_write(&kdbus_node_idr_lock);

		kfree(safe.name);
		kdbus_node_unref(safe.parent);
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
	if (atomic_read(&node->active) == KDBUS_NODE_NEW) {
		atomic_sub(KDBUS_NODE_NEW, &node->active);
		/* activated nodes have ref +1 */
		kdbus_node_ref(node);
	}
	mutex_unlock(&node->lock);
}

/**
 * kdbus_node_deactivate() - deactivate a node
 * @node:	The node to deactivate.
 *
 * This function recursively deactivates the node and all its children.
 */
void kdbus_node_deactivate(struct kdbus_node *node)
{
	struct kdbus_node *pos, *child;
	struct rb_node *rb;
	int v;

	pos = node;

	/*
	 * To avoid recursion, we perform back-tracking while deactivating
	 * nodes. For each node we enter, we first mark the active-counter as
	 * deactivated by adding BIAS. If the node as children, we set the first
	 * child as current position and start over. If the node has no
	 * children, we drain the node by waiting for all active refs to be
	 * dropped and then releasing the node.
	 *
	 * After the node is released, we set its parent as current position
	 * and start over. If the current position was the initial node, we're
	 * done.
	 *
	 * Note that this function can be called in parallel by multiple
	 * callers. We make sure that each node is only released once, and any
	 * racing caller will wait until the other thread fully released that
	 * node.
	 */

	for (;;) {
		/* add BIAS to node->active to mark it as inactive */
		mutex_lock(&pos->lock);
		v = atomic_read(&pos->active);
		if (v >= 0)
			atomic_add_return(KDBUS_NODE_BIAS, &pos->active);
		else if (v == KDBUS_NODE_NEW)
			atomic_add_return(3, &pos->active);
		mutex_unlock(&pos->lock);

		/* wait until all active references were dropped */
		wait_event(pos->waitq,
			   atomic_read(&pos->active) <= KDBUS_NODE_BIAS);

		mutex_lock(&pos->lock);
		/* recurse into first child if any */
		rb = rb_first(&pos->children);
		if (rb) {
			child = kdbus_node_ref(kdbus_node_from_rb(rb));
			mutex_unlock(&pos->lock);
			pos = child;
			continue;
		}

		/* mark object as RELEASE */
		v = atomic_read(&pos->active);
		if (v == KDBUS_NODE_BIAS)
			atomic_dec(&pos->active);
		mutex_unlock(&pos->lock);

		/*
		 * If this is the thread that marked the object as RELEASE, we
		 * perform the actual release. Otherwise, we wait until the
		 * release is done and the node is marked as DRAINED.
		 */
		if (v == KDBUS_NODE_BIAS) {
			if (pos->release_cb)
				pos->release_cb(pos);

			if (pos->parent) {
				mutex_lock(&pos->parent->lock);
				if (!RB_EMPTY_NODE(&pos->rb)) {
					rb_erase(&pos->rb, &pos->parent->children);
					RB_CLEAR_NODE(&pos->rb);
				}
				mutex_unlock(&pos->parent->lock);
			}

			/* activated nodes have ref +1, drop it */
			kdbus_node_unref(pos);

			/* mark as DRAINED */
			atomic_dec(&pos->active);
			wake_up_all(&pos->waitq);
		} else {
			/* wait until object is DRAINED */
			wait_event(pos->waitq,
				   atomic_read(&pos->active) == KDBUS_NODE_DRAINED);
		}

		/*
		 * We're done with the current node. Continue on its parent
		 * again, which will try deactivating its next child, or itself
		 * if no child is left.
		 * If we've reached our initial node again, we are done and
		 * can safely return.
		 */
		if (pos == node)
			break;

		child = pos;
		pos = pos->parent;
		kdbus_node_unref(child);
	}
}

/**
 * kdbus_node_acquire() - Acquire an active ref on a node
 * @node:	The node
 *
 * Return: %true if @node was non-NULL and not deactivated.
 */
bool kdbus_node_acquire(struct kdbus_node *node)
{
	return node && atomic_inc_unless_negative(&node->active);
}

/**
 * kdbus_node_release() - Release an active ref on a node
 * @node:	The node
 *
 * If the call this function releases is the last active counter on the node,
 * the parallel draining thread will return.
 */
void kdbus_node_release(struct kdbus_node *node)
{
	if (node && atomic_dec_return(&node->active) == KDBUS_NODE_BIAS)
		wake_up(&node->waitq);
}
