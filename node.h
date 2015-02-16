/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
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
#include <linux/mutex.h>
#include <linux/wait.h>

struct kdbus_node;

enum kdbus_node_type {
	KDBUS_NODE_DOMAIN,
	KDBUS_NODE_CONTROL,
	KDBUS_NODE_BUS,
	KDBUS_NODE_ENDPOINT,
};

typedef void (*kdbus_node_free_t) (struct kdbus_node *node);
typedef void (*kdbus_node_release_t) (struct kdbus_node *node, bool was_active);

struct kdbus_node {
	atomic_t refcnt;
	atomic_t active;
	wait_queue_head_t waitq;

	/* static members */
	unsigned int type;
	kdbus_node_free_t free_cb;
	kdbus_node_release_t release_cb;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;

	/* valid once linked */
	char *name;
	unsigned int hash;
	unsigned int id;
	struct kdbus_node *parent; /* may be NULL */

	/* valid iff active */
	struct mutex lock;
	struct rb_node rb;
	struct rb_root children;
};

#define kdbus_node_from_rb(_node) rb_entry((_node), struct kdbus_node, rb)

void kdbus_node_init(struct kdbus_node *node, unsigned int type);

int kdbus_node_link(struct kdbus_node *node, struct kdbus_node *parent,
		    const char *name);

struct kdbus_node *kdbus_node_ref(struct kdbus_node *node);
struct kdbus_node *kdbus_node_unref(struct kdbus_node *node);

bool kdbus_node_is_active(struct kdbus_node *node);
bool kdbus_node_is_deactivated(struct kdbus_node *node);
bool kdbus_node_activate(struct kdbus_node *node);
void kdbus_node_deactivate(struct kdbus_node *node);

bool kdbus_node_acquire(struct kdbus_node *node);
void kdbus_node_release(struct kdbus_node *node);

struct kdbus_node *kdbus_node_find_child(struct kdbus_node *node,
					 const char *name);
struct kdbus_node *kdbus_node_find_closest(struct kdbus_node *node,
					   unsigned int hash);
struct kdbus_node *kdbus_node_next_child(struct kdbus_node *node,
					 struct kdbus_node *prev);

#endif
