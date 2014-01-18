/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_NS_H
#define __KDBUS_NS_H

#include <linux/hashtable.h>
#include <linux/idr.h>

/**
 * struct kdbus_namespace - namespace for buses
 * @kref:		Reference counter
 * @disconnected:	Invalidated data
 * @name:		Name of the namespace
 * @parent:		Parent namespace
 * @ns_list:		List of child namespaces
 * @id:			Global id of this namespace
 * @devpath:		/dev base directory path
 * @major:		Device major number for all nodes
 * @mode:		Device node access mode
 * @idr:		Map of endpoint minors to buses
 * @dev:		Control device node, minor == 0
 * @lock:		Namespace data lock
 * @bus_seq_last:	Last used bus id sequence number
 * @msg_seq_last:	Last used message id sequence number
 * @ns_entry:		Entry in parent namespace
 * @bus_list:		Buses in this namespace
 * @user_hash:		Accounting of user resources
 *
 * A namespace provides a "control" device node. Every namespace has its
 * own major number for its endpoint device nodes.
 *
 * The initial namespace is created at initialization time, is unnamed and
 * stays around for forver.
 *
 * A namespace is created by opening the "control" device node of the
 * parent namespace and issuing the KDBUS_CMD_NS_MAKE iotcl. Closing this
 * file immediately destroys the entire namespace.
 */
struct kdbus_ns {
	struct kref kref;
	bool disconnected;
	const char *name;
	struct kdbus_ns *parent;
	struct list_head ns_list;
	u64 id;
	const char *devpath;
	unsigned int major;
	umode_t mode;
	struct idr idr;
	struct device *dev;
	struct mutex lock;
	u64 bus_seq_last;
	atomic64_t msg_seq_last;
	struct list_head ns_entry;
	struct list_head bus_list;
	DECLARE_HASHTABLE(user_hash, 6);
};

/**
 * struct kdbus_ns_user - resource accounting for users
 * @kref:		Reference counter
 * @ns:			Namespace of the user
 * @hentry:		Entry in namespace user map
 * @uid:		UID of the user
 * @buses:		Number of buses the user has created
 * @connections:	Number of connections the user has created
 */
struct kdbus_ns_user {
	struct kref kref;
	struct kdbus_ns *ns;
	struct hlist_node hentry;
	kuid_t uid;
	atomic_t buses;
	atomic_t connections;
};

extern struct kdbus_ns *kdbus_ns_init;
extern struct bus_type kdbus_subsys;

struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns);
struct kdbus_ns *kdbus_ns_unref(struct kdbus_ns *ns);
void kdbus_ns_disconnect(struct kdbus_ns *ns);
int kdbus_ns_new(struct kdbus_ns *parent, const char *name,
		 umode_t mode, struct kdbus_ns **ns);
int kdbus_ns_make_user(void __user *buf,
		       struct kdbus_cmd_make **make, char **name);
struct kdbus_ns *kdbus_ns_find_by_major(unsigned int major);

struct kdbus_ns_user *kdbus_ns_user_ref(struct kdbus_ns *ns, kuid_t uid);
struct kdbus_ns_user *kdbus_ns_user_unref(struct kdbus_ns_user *user);
#endif
