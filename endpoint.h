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

#ifndef __KDBUS_EP_H
#define __KDBUS_EP_H

#include "internal.h"

/*
 * kdbus endpoint
 * - offers access to a bus, the default device node name is "bus"
 * - additional endpoints can carry a specific policy/filters
 */
struct kdbus_ep {
	struct kref kref;		/* reference count */
	bool disconnected;		/* invalidated data */
	struct kdbus_bus *bus;		/* bus behind this endpoint */
	const char *name;		/* name, prefixed with uid */
	u64 id;				/* id of this endpoint on the bus */
	unsigned int minor;		/* minor of this endpoint in the namespace major */
	struct device *dev;		/* device node of this endpoint */
	umode_t mode;			/* file mode of this endpoint device node */
	kuid_t uid;			/* uid owning this endpoint */
	kgid_t gid;			/* gid owning this endpoint */
	struct list_head bus_entry;	/* bus' endpoints */
	wait_queue_head_t wait;		/* wake up this endpoint */
	struct kdbus_policy_db *policy_db;
	bool policy_open:1;
};

struct kdbus_cmd_ep_kmake {
	const char *name;
	struct kdbus_cmd_ep_make make;
};

struct kdbus_ep *kdbus_ep_ref(struct kdbus_ep *ep);
void kdbus_ep_unref(struct kdbus_ep *ep);

int kdbus_ep_new(struct kdbus_bus *bus, const char *name,
		 umode_t mode, kuid_t uid, kgid_t gid, bool policy);
int kdbus_ep_remove(struct kdbus_ep *ep);
void kdbus_ep_disconnect(struct kdbus_ep *ep);
int kdbus_ep_kmake_user(void __user *buf, struct kdbus_cmd_ep_kmake **kmake);
#endif
