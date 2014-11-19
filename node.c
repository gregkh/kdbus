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

/* global unique ID mapping for kdbus nodes */
static DEFINE_IDR(kdbus_node_idr);
static DECLARE_RWSEM(kdbus_node_idr_lock);

/**
 * kdbus_node_name_hash() - hash a name
 * @name:	The string to hash
 *
 * This computes the hash of @name. It is guaranteed to be in the range
 * [2..INT_MAX-1]. The values 1, 2 and INT_MAX are unused as they are reserved
 * for the filesystem code.
 *
 * Return: hash value of the passed string
 */
static unsigned int kdbus_node_name_hash(const char *name)
{
	unsigned int hash;

	/* reserve hash numbers 0, 1 and >=INT_MAX for magic directories */
	hash = kdbus_str_hash(name) & INT_MAX;
	if (hash < 2)
		hash += 2;
	if (hash >= INT_MAX)
		hash = INT_MAX - 1;

	return hash;
}

/**
 * kdbus_node_name_compare() - compare a name with a node's name
 * @hash:	hash of the string to compare the node with
 * @name:	name to compare the node with
 * @node:	node to compare the name with
 *
 * Return: 0 if @name and @hash exactly match the information in @node, or
 * an integer less than or greater than zero if @name is found, respectively,
 * to be less than or be greater than the string stored in @node.
 */
static int kdbus_node_name_compare(unsigned int hash, const char *name,
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
 */
void kdbus_node_init(struct kdbus_node *node, unsigned int type)
{
	atomic_set(&node->refcnt, 1);
	mutex_init(&node->lock);
	node->id = 0;
	node->type = type;
	RB_CLEAR_NODE(&node->rb);
	node->children = RB_ROOT;
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
	ret = idr_alloc(&kdbus_node_idr, node, 1, 0, GFP_KERNEL);
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
					rb_erase(&pos->rb,
						 &pos->parent->children);
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

/**
 * kdbus_node_find_child() - Find child by name
 * @node:	parent node to search through
 * @name:	name of child node
 *
 * This searches through all children of @node for a child-node with name @name.
 * If not found, or if the child is deactivated, NULL is returned. Otherwise,
 * the child is acquired and a new reference is returned.
 *
 * If you're done with the child, you need to release it and drop your
 * reference.
 *
 * This function does not acquire the parent node. However, if the parent was
 * already deactivated, then kdbus_node_deactivate() will, at some point, also
 * deactivate the child. Therefore, we can rely on the explicit ordering during
 * deactivation.
 *
 * Return: Reference to acquired child node, or NULL if not found / not active.
 */
struct kdbus_node *kdbus_node_find_child(struct kdbus_node *node,
					 const char *name)
{
	struct kdbus_node *child;
	struct rb_node *rb;
	unsigned int hash;
	int ret;

	hash = kdbus_node_name_hash(name);

	mutex_lock(&node->lock);
	rb = node->children.rb_node;
	while (rb) {
		child = kdbus_node_from_rb(rb);
		ret = kdbus_node_name_compare(hash, name, child);
		if (ret < 0)
			rb = rb->rb_left;
		else if (ret > 0)
			rb = rb->rb_right;
		else
			break;
	}
	if (rb && kdbus_node_acquire(child))
		kdbus_node_ref(child);
	else
		child = NULL;
	mutex_unlock(&node->lock);

	return child;
}

static struct kdbus_node *node_find_closest_unlocked(struct kdbus_node *node,
						     unsigned int hash)
{
	struct kdbus_node *n, *pos = NULL;
	struct rb_node *rb;

	/* find the closest child with ``node->hash >= hash'' */
	rb = node->children.rb_node;
	while (rb) {
		n = kdbus_node_from_rb(rb);
		if (hash <= n->hash) {
			rb = rb->rb_left;
			pos = n;
		} else  { /* ``hash > n->hash'' */
			rb = rb->rb_right;
		}
	}

	return pos;
}

/**
 * kdbus_node_find_closest() - Find closest child-match
 * @node:	parent node to search through
 * @hash:	hash value to find closest match for
 *
 * Find the closest child of @node with a hash greater than or equal to @hash.
 * The closest match is the left-most child of @node with this property. Which
 * means, it is the first child with that hash returned by
 * kdbus_node_next_child(), if you'd iterate the whole parent node.
 *
 * Return: Reference to acquired child, or NULL if none found.
 */
struct kdbus_node *kdbus_node_find_closest(struct kdbus_node *node,
					   unsigned int hash)
{
	struct kdbus_node *child;
	struct rb_node *rb;

	mutex_lock(&node->lock);

	child = node_find_closest_unlocked(node, hash);
	while (child && !kdbus_node_acquire(child)) {
		rb = rb_next(&child->rb);
		if (rb)
			child = kdbus_node_from_rb(rb);
		else
			child = NULL;
	}
	kdbus_node_ref(child);

	mutex_unlock(&node->lock);

	return child;
}

/**
 * kdbus_node_next_child() - Acquire next child
 * @node:	parent node
 * @prev:	previous child-node position or NULL
 *
 * This function returns a reference to the next active child of @node, after
 * the passed position @prev. If @prev is NULL, a reference to the first active
 * child is returned. If no more active children are found, NULL is returned.
 *
 * This function acquires the next child it returns. If you're done with the
 * returned pointer, you need to release _and_ unref it.
 *
 * The passed in pointer @prev is not modified by this function, and it does
 * *not* have to be active. If @prev was acquired via different means, or if it
 * was unlinked from its parent before you pass it in, then this iterator will
 * still return the next active child (it will have to search through the
 * rb-tree based on the node-name, though).
 * However, @prev must not be linked to a different parent than @node!
 *
 * Return: Reference to next acquired child, or NULL if at the end.
 */
struct kdbus_node *kdbus_node_next_child(struct kdbus_node *node,
					 struct kdbus_node *prev)
{
	struct kdbus_node *pos = NULL;
	struct rb_node *rb;

	mutex_lock(&node->lock);

	if (!prev) {
		/*
		 * New iteration; find first node in rb-tree and try to acquire
		 * it. If we got it, directly return it as first element.
		 * Otherwise, the loop below will find the next active node.
		 */
		rb = rb_first(&node->children);
		if (!rb)
			goto exit;
		pos = kdbus_node_from_rb(rb);
		if (kdbus_node_acquire(pos))
			goto exit;
	} else if (RB_EMPTY_NODE(&prev->rb)) {
		/*
		 * The current iterator is no longer linked to the rb-tree. Use
		 * its hash value to find the next _higher_ node and acquire it.
		 * If we got it, return it as next element. Otherwise, the loop
		 * below will find the next active node.
		 */
		pos = node_find_closest_unlocked(node, prev->hash);
		if (!pos)
			goto exit;
		if (kdbus_node_acquire(pos))
			goto exit;
	} else {
		/*
		 * The current iterator is still linked to the parent. Set it
		 * as current position and use the loop below to find the next
		 * active element.
		 */
		pos = prev;
	}

	/* @pos was already returned or is inactive; find next active node */
	do {
		rb = rb_next(&pos->rb);
		if (rb)
			pos = kdbus_node_from_rb(rb);
		else
			pos = NULL;
	} while (pos && !kdbus_node_acquire(pos));

exit:
	/* @pos is NULL or acquired. Take ref if non-NULL and return it */
	kdbus_node_ref(pos);
	mutex_unlock(&node->lock);
	return pos;
}
