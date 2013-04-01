/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 */

#ifndef __INTERNAL_KDBUS_H
#define __INTERNAL_KDBUS_H

#include <uapi/linux/major.h>
#include "kdbus.h"

/* FIXME: move to uapi/linux/major.h */
#define KDBUS_CHAR_MAJOR	222


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
	unsigned int ref;		/* reference count */
	const char *name;		/* name of the namespace */
	bool disconnected;		/* invalidated data */
	struct kdbus_ns *parent;	/* parent namespace */
	u64 id;				/* global id of this namespace */
	const char *devpath;		/* /dev base directory path */
	int major;			/* device major number for all nodes */
	struct idr idr;			/* map of endpoint minors to buses */
	struct device *dev;		/* control device node, minor == 0 */
	struct mutex lock;		/* ns data lock */
	u64 bus_id_next;		/* next bus id sequence number */
	struct list_head list_entry;
};

/* names registry */
struct kdbus_name_registry {
	struct kref		kref;
	struct list_head	entries_list;
	struct mutex		entries_lock;
};

struct kdbus_name_entry {
	char 			*name;
	u32			hash;
	u64			flags;
	struct list_head	queue_list;
	struct list_head	registry_entry;
	struct list_head	conn_entry;
	struct kdbus_conn	*conn;
};

struct kdbus_name_queue_item {
	struct kdbus_conn 	*conn;
	struct kdbus_name_entry	*entry;
	u64			 flags;
	struct list_head	 entry_entry;
	struct list_head	 conn_entry;
};

struct kdbus_name_registry *kdbus_name_registry_new(void);
void kdbus_name_registry_unref(struct kdbus_name_registry *reg);

int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       void __user *buf);
int kdbus_name_release(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn,
		       void __user *buf);
int kdbus_name_list(struct kdbus_name_registry *reg,
		    struct kdbus_conn *conn,
		    void __user *buf);
int kdbus_name_query(struct kdbus_name_registry *reg,
		     struct kdbus_conn *conn,
		     void __user *buf);

struct kdbus_name_entry *kdbus_name_lookup(struct kdbus_name_registry *reg,
					   const char *name, u64 type);
void kdbus_name_remove_by_conn(struct kdbus_name_registry *reg,
			       struct kdbus_conn *conn);

/*
 * kdbus bus
 * - provides a "bus" endpoint
 * - owns additional endpoints
 * - own all bus connections
 * - new buses are created by opening the control node and
 *   issuing KDBUS_BUS_CREATE
 * - closing the connection destroys the created bus
 */
struct kdbus_bus {
	struct kref kref;		/* reference count */
	bool disconnected;		/* invalidated data */
	struct kdbus_ns *ns;		/* namespace of this bus */
	const char *name;		/* bus name */
	u64 id;				/* id of this bus in the namespace */
	struct mutex lock;		/* bus data lock */
	u64 ep_id_next;			/* next endpoint id sequence number */
	u64 conn_id_next;		/* next connection id sequence number */
	u64 msg_id_next;		/* next message id sequence number */
	struct idr conn_idr;		/* map of connection ids */
	struct kdbus_ep *ep;		/* "bus" default endpoint */
	struct list_head ep_list;	/* endpoints assigned to this bus */
	u64 bus_flags;			/* simple pass-thru flags from userspace to userspace */
	struct kdbus_name_registry *name_registry;
};

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
	uid_t uid;			/* uid owning this endpoint */
	gid_t gid;			/* gid owning this endpoint */
	struct list_head bus_entry;	/* list of endpoints for this bus */
	struct list_head message_list;	/* messages in flight for this endpoint */
	struct list_head connection_list;
	wait_queue_head_t wait;		/* wake up this endpoint */
};

/*
 * kdbus connection
 * - connection to a control node or an endpoint
 */
enum kdbus_conn_type {
	KDBUS_CONN_UNDEFINED,
	KDBUS_CONN_CONTROL,
	KDBUS_CONN_NS_OWNER,
	KDBUS_CONN_BUS_OWNER,
	KDBUS_CONN_EP,
};

struct kdbus_conn {
	enum kdbus_conn_type type;
	struct kdbus_ns *ns;
	union {
		struct kdbus_ns *ns_owner;
		struct kdbus_bus *bus_owner;
		struct kdbus_ep *ep;
	};
	u64 id;		/* id of the connection on the bus */

	bool active;	/* did the connection say hello yet? */

	/*
	 * first, horrible cut at messages assigned to connections
	 * odds are, this is going to be slow, but let's measure it first to
	 * see what the real numbers are, and where the bottlenecks are.
	 * Premature optimization and all...
	 */
	struct mutex msg_lock;
	struct list_head msg_list;

	/* Ugh a list of all connections in the system?  Ugly, but we need to
	 * be able to walk them all somehow.  Maybe just have a list on the
	 * endpoints of the connections associated with that endpoint?  That's
	 * all we really need in the end... */
	struct list_head connection_entry;

	struct list_head names_list;
	struct list_head names_queue_list;
};

struct kdbus_kmsg {
	struct kref kref;
	struct kdbus_msg msg;
};

struct kdbus_msg_list_entry {
	struct kdbus_kmsg *kmsg;
	struct list_head list;
};

int kdbus_kmsg_new(struct kdbus_conn *conn, uint64_t extra_size,
		   struct kdbus_kmsg **m);
int kdbus_kmsg_new_from_user(struct kdbus_conn *conn, void __user *argp,
			     struct kdbus_kmsg **m);
void kdbus_kmsg_unref(struct kdbus_kmsg *kmsg);
int kdbus_kmsg_send(struct kdbus_ep *ep, struct kdbus_kmsg *kmsg);
int kdbus_kmsg_recv(struct kdbus_conn *conn, void __user *buf);

/* namespace */
extern const struct file_operations kdbus_device_ops;
extern struct mutex kdbus_subsys_lock;
extern struct idr kdbus_ns_major_idr;
struct kdbus_ns *kdbus_ns_ref(struct kdbus_ns *ns);
void kdbus_ns_disconnect(struct kdbus_ns *ns);
struct kdbus_ns *kdbus_ns_unref(struct kdbus_ns *ns);
int kdbus_ns_new(struct kdbus_ns *parent, const char *name, umode_t mode, struct kdbus_ns **ns);
struct kdbus_ns *kdbus_ns_find(const char *name);


/* bus */
extern struct bus_type kdbus_subsys;
void kdbus_release(struct device *dev);

struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus);
void kdbus_bus_unref(struct kdbus_bus *bus);
void kdbus_bus_disconnect(struct kdbus_bus *bus);
int kdbus_bus_new(struct kdbus_ns *ns, const char *name, umode_t mode,
		  u64 bus_flags, uid_t uid, gid_t gid, struct kdbus_bus **bus);

/* endpoint */
struct kdbus_ep *kdbus_ep_ref(struct kdbus_ep *ep);
void kdbus_ep_unref(struct kdbus_ep *ep);

struct kdbus_ep *kdbus_ep_find(struct kdbus_bus *bus, const char *name);
int kdbus_ep_new(struct kdbus_bus *bus, const char *name, umode_t mode,
		 uid_t uid, gid_t gid, struct kdbus_ep **ep);
int kdbus_ep_remove(struct kdbus_ep *ep);
void kdbus_ep_disconnect(struct kdbus_ep *ep);

#endif
