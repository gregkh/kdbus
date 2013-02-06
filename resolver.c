/*
 * kdbus - interprocess message routing
 *
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>
//#include <uapi/linux/major.h>
#include "kdbus.h"

#include "kdbus_internal.h"


/*
 * Resolver
 *
 * Think of this as DNS in the kernel.
 *
 * Ok, now that you feel sick to your stomach, let's move on.
 *
 * We need a way to associate a "name" with a connection id.  We can have
 * multiple names associated with a single id.
 *
 * All of this is unique to a specific namespace, names and ids can't cross
 * namespace boundries.
 *
 * Things we can do:
 *   - query for a list of all names and their associated ids
 *   - query for all ids
 *   - set the name for an id
 *   - remove the name for an id
 *
 * when an ID is removed from the system, all names for it are also removed.
 */

int resolve_remove_id(void)
{
	return 0;
}

int resolve_set_name_id(void)
{
	return 0;
}

int resolve_query_list_names(void)
{
	return 0;
}

int resolve_query_list_ids(void)
{
	return 0;
}

int resolve_id_added(void)
{
	return 0;
}

int resolve_id_removed(void)
{
	return 0;
}



