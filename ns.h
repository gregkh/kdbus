/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_NS_H
#define __KDBUS_NS_H

#include "internal.h"

/*
 * kdbus namespace
 * - provides a "control" node
 * - owns a major number
 * - owns all created buses
 * - the initial namespace is unnamed and stays around for forver
 * - new namespaces are created by opening the control node and
 *   issuing KDBUS_NS_CREATE
 * - closing the connection destroys the created namespace
 */
struct kdbus_ns {
	struct kref kref;		/* reference counter */
	const char *name;		/* name of the namespace */
	struct kdbus_ns *parent;	/* parent namespace */
	u64 id;				/* global id of this namespace */
	const char *devpath;		/* /dev base directory path */
	int major;			/* device major number for all nodes */
	umode_t mode;			/* device node access mode */
	struct idr idr;			/* map of endpoint minors to buses */
	struct device *dev;		/* control device node, minor == 0 */
	struct mutex lock;		/* ns data lock */
	u64 bus_id_next;		/* next bus id sequence number */
	struct list_head ns_entry;
	struct list_head bus_list;	/* list of all buses */
};

struct kdbus_cmd_ns_kmake {
	const char *name;
	struct kdbus_cmd_ns_make make;
};

struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns);
void kdbus_ns_unref(struct kdbus_ns *ns);
void kdbus_ns_disconnect(struct kdbus_ns *ns);
int kdbus_ns_new(struct kdbus_ns *parent, const char *name, umode_t mode, struct kdbus_ns **ns);
int kdbus_ns_kmake_user(void __user *buf, struct kdbus_cmd_ns_kmake **kmake);
struct kdbus_ns *kdbus_ns_find_by_major(int major);
#endif
