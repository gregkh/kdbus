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

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "bus.h"
#include "notify.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "item.h"
#include "metadata.h"
#include "names.h"
#include "policy.h"

static void kdbus_bus_free(struct kdbus_node *node);
static void kdbus_bus_release(struct kdbus_node *node);

/**
 * kdbus_bus_new() - create a kdbus_cmd_make from user-supplied data
 * @domain:		The domain to work on
 * @make:		Information as passed in by userspace
 * @mode:		The access mode for the device node
 * @uid:		The uid of the device node
 * @gid:		The gid of the device node
 *
 * This function is part of the connection ioctl() interface and will parse
 * the user-supplied data in order to create a new kdbus_bus.
 *
 * Return: the new bus on success, ERR_PTR on failure.
 */
struct kdbus_bus *kdbus_bus_new(struct kdbus_domain *domain,
				const struct kdbus_cmd_make *make,
				umode_t mode, kuid_t uid, kgid_t gid)
{
	const struct kdbus_bloom_parameter *bloom = NULL;
	const struct kdbus_item *item;
	struct kdbus_bus *b;
	const char *name = NULL;
	char prefix[16];
	int ret;

	u64 attach_flags = 0;

	KDBUS_ITEMS_FOREACH(item, make->items, KDBUS_ITEMS_SIZE(make, items)) {
		switch (item->type) {
		case KDBUS_ITEM_MAKE_NAME:
			if (name)
				return ERR_PTR(-EEXIST);

			name = item->str;
			break;

		case KDBUS_ITEM_BLOOM_PARAMETER:
			if (bloom)
				return ERR_PTR(-EEXIST);

			bloom = &item->bloom_parameter;
			break;

		case KDBUS_ITEM_ATTACH_FLAGS_RECV:
			if (attach_flags)
				return ERR_PTR(-EEXIST);

			attach_flags = item->data64[0];
			break;
		}
	}

	if (!name || !bloom)
		return ERR_PTR(-EBADMSG);

	/* 'any' degrades to 'all' for compatibility */
	if (attach_flags == _KDBUS_ATTACH_ANY)
		attach_flags = _KDBUS_ATTACH_ALL;

	/* reject unknown attach flags */
	if (attach_flags & ~_KDBUS_ATTACH_ALL)
		return ERR_PTR(-EINVAL);
	if (bloom->size < 8 || bloom->size > KDBUS_BUS_BLOOM_MAX_SIZE)
		return ERR_PTR(-EINVAL);
	if (!KDBUS_IS_ALIGNED8(bloom->size))
		return ERR_PTR(-EINVAL);
	if (bloom->n_hash < 1)
		return ERR_PTR(-EINVAL);

	/* enforce "$UID-" prefix */
	snprintf(prefix, sizeof(prefix), "%u-",
		 from_kuid(current_user_ns(), uid));
	if (strncmp(name, prefix, strlen(prefix) != 0))
		return ERR_PTR(-EINVAL);

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return ERR_PTR(-ENOMEM);

	b->uid_owner = uid;
	b->bus_flags = make->flags;
	b->bloom = *bloom;
	b->attach_flags_req = attach_flags;
	mutex_init(&b->lock);
	init_rwsem(&b->conn_rwlock);
	hash_init(b->conn_hash);
	INIT_LIST_HEAD(&b->ep_list);
	INIT_LIST_HEAD(&b->monitors_list);
	INIT_LIST_HEAD(&b->notify_list);
	spin_lock_init(&b->notify_lock);
	mutex_init(&b->notify_flush_lock);
	atomic64_set(&b->conn_seq_last, 0);
	b->domain = kdbus_domain_ref(domain);
	kdbus_policy_db_init(&b->policy_db);
	b->id = atomic64_inc_return(&domain->bus_seq_last);

	/* generate unique bus id */
	generate_random_uuid(b->id128);

	ret = kdbus_node_init(&b->node, &domain->node,
			      KDBUS_NODE_BUS, name,
			      kdbus_bus_free, kdbus_bus_release);
	if (ret < 0)
		goto exit_unref;

	b->node.mode = 0755;

	/* cache the metadata/credentials of the creator */
	b->meta = kdbus_meta_new();
	if (IS_ERR(b->meta)) {
		ret = PTR_ERR(b->meta);
		goto exit_unref;
	}

	ret = kdbus_meta_append(b->meta, NULL, 0,
				KDBUS_ATTACH_CREDS	|
				KDBUS_ATTACH_TID_COMM	|
				KDBUS_ATTACH_PID_COMM	|
				KDBUS_ATTACH_EXE	|
				KDBUS_ATTACH_CMDLINE	|
				KDBUS_ATTACH_CGROUP	|
				KDBUS_ATTACH_CAPS	|
				KDBUS_ATTACH_SECLABEL	|
				KDBUS_ATTACH_AUDIT);
	if (ret < 0)
		goto exit_unref;

	b->name_registry = kdbus_name_registry_new();
	if (IS_ERR(b->name_registry)) {
		ret = PTR_ERR(b->name_registry);
		goto exit_unref;
	}

	b->user = kdbus_domain_get_user(domain, uid);
	if (IS_ERR(b->user)) {
		ret = PTR_ERR(b->user);
		goto exit_unref;
	}

	if (atomic_inc_return(&b->user->buses) > KDBUS_USER_MAX_BUSES) {
		ret = -EMFILE;
		goto exit_unref;
	}

	b->ep = kdbus_ep_new(b, "bus", mode, uid, gid, false);
	if (IS_ERR(b->ep)) {
		ret = PTR_ERR(b->ep);
		goto exit_unref;
	}

	return b;

exit_unref:
	kdbus_node_unref(&b->node);
	return ERR_PTR(ret);
}

static void kdbus_bus_free(struct kdbus_node *node)
{
	struct kdbus_bus *bus = container_of(node, struct kdbus_bus, node);

	BUG_ON(kdbus_bus_is_active(bus));
	BUG_ON(!list_empty(&bus->ep_list));
	BUG_ON(!list_empty(&bus->monitors_list));
	BUG_ON(!hash_empty(bus->conn_hash));

	kdbus_notify_free(bus);

	if (bus->user) {
		atomic_dec(&bus->user->buses);
		kdbus_domain_user_unref(bus->user);
	}

	kdbus_name_registry_free(bus->name_registry);
	kdbus_domain_unref(bus->domain);
	kdbus_policy_db_clear(&bus->policy_db);
	kdbus_meta_free(bus->meta);
	kfree(bus);
}

/**
 * kdbus_bus_ref() - increase the reference counter of a kdbus_bus
 * @bus:		The bus to reference
 *
 * Every user of a bus, except for its creator, must add a reference to the
 * kdbus_bus using this function.
 *
 * Return: the bus itself
 */
struct kdbus_bus *kdbus_bus_ref(struct kdbus_bus *bus)
{
	if (bus)
		kdbus_node_ref(&bus->node);
	return bus;
}

/**
 * kdbus_bus_unref() - decrease the reference counter of a kdbus_bus
 * @bus:		The bus to unref
 *
 * Release a reference. If the reference count drops to 0, the bus will be
 * freed.
 *
 * Return: NULL
 */
struct kdbus_bus *kdbus_bus_unref(struct kdbus_bus *bus)
{
	if (!bus)
		return NULL;

	kdbus_node_unref(&bus->node);
	return NULL;
}

/**
 * kdbus_bus_activate() - activate a bus
 * @bus:		Bus
 *
 * Activate a bus and make it available to user-space.
 *
 * Returns: 0 on success, negative error code on failure
 */
int kdbus_bus_activate(struct kdbus_bus *bus)
{
	int ret;

	mutex_lock(&bus->domain->lock);

	if (!kdbus_domain_is_active(bus->domain)) {
		mutex_unlock(&bus->domain->lock);
		return -ESHUTDOWN;
	}

	list_add_tail(&bus->domain_entry, &bus->domain->bus_list);
	kdbus_node_activate(&bus->node);

	mutex_unlock(&bus->domain->lock);

	ret = kdbus_ep_activate(bus->ep);
	if (ret < 0) {
		kdbus_bus_deactivate(bus);
		return ret;
	}

	return 0;
}

static void kdbus_bus_release(struct kdbus_node *node)
{
	struct kdbus_bus *bus = container_of(node, struct kdbus_bus, node);

	/* disconnect from domain */
	mutex_lock(&bus->domain->lock);
	list_del(&bus->domain_entry);
	mutex_unlock(&bus->domain->lock);

	/* disconnect all endpoints attached to this bus */
	for (;;) {
		struct kdbus_ep *ep;

		mutex_lock(&bus->lock);
		ep = list_first_entry_or_null(&bus->ep_list,
					      struct kdbus_ep,
					      bus_entry);
		if (!ep) {
			mutex_unlock(&bus->lock);
			break;
		}

		/* take reference, release lock, disconnect without lock */
		kdbus_ep_ref(ep);
		mutex_unlock(&bus->lock);

		kdbus_ep_deactivate(ep);
		kdbus_ep_unref(ep);
	}

	/* drop reference for our "bus" endpoint after we disconnected */
	bus->ep = kdbus_ep_unref(bus->ep);
}

/**
 * kdbus_bus_deactivate() - deactivate a bus
 * @bus:               The kdbus reference
 *
 * The passed bus will be disconnected and the associated endpoint will be
 * unref'ed.
 */
void kdbus_bus_deactivate(struct kdbus_bus *bus)
{
	kdbus_node_deactivate(&bus->node);
	kdbus_node_drain(&bus->node);
}

/**
 * kdbus_bus_find_conn_by_id() - find a connection with a given id
 * @bus:		The bus to look for the connection
 * @id:			The 64-bit connection id
 *
 * Looks up a connection with a given id. The returned connection
 * is ref'ed, and needs to be unref'ed by the user. Returns NULL if
 * the connection can't be found.
 */
struct kdbus_conn *kdbus_bus_find_conn_by_id(struct kdbus_bus *bus, u64 id)
{
	struct kdbus_conn *conn, *found = NULL;

	down_read(&bus->conn_rwlock);
	hash_for_each_possible(bus->conn_hash, conn, hentry, id)
		if (conn->id == id) {
			found = kdbus_conn_ref(conn);
			break;
		}
	up_read(&bus->conn_rwlock);

	return found;
}

/**
 * kdbus_cmd_bus_creator_info() - get information on a bus creator
 * @conn:	The querying connection
 * @cmd_info:	The command buffer, as passed in from the ioctl
 *
 * Gather information on the creator of the bus @conn is connected to.
 *
 * Return: 0 on success, error otherwise.
 */
int kdbus_cmd_bus_creator_info(struct kdbus_conn *conn,
			       struct kdbus_cmd_info *cmd_info)
{
	struct kdbus_bus *bus = conn->bus;
	struct kdbus_pool_slice *slice;
	struct kdbus_info info = {};
	int ret;

	if (!kdbus_meta_ns_eq(conn->meta, bus->meta))
		return -EPERM;

	info.id = bus->id;
	info.flags = bus->bus_flags;
	info.size = sizeof(info) +
		    kdbus_meta_size(bus->meta, conn, cmd_info->flags);

	slice = kdbus_pool_slice_alloc(conn->pool, info.size);
	if (IS_ERR(slice))
		return PTR_ERR(slice);

	ret = kdbus_pool_slice_copy(slice, 0, &info, sizeof(info));
	if (ret < 0)
		goto exit_free_slice;

	ret = kdbus_meta_write(bus->meta, conn, cmd_info->flags,
			       slice, sizeof(info));
	if (ret < 0)
		goto exit_free_slice;

	/* write back the offset */
	cmd_info->offset = kdbus_pool_slice_offset(slice);
	kdbus_pool_slice_flush(slice);
	kdbus_pool_slice_make_public(slice);

	return 0;

exit_free_slice:
	kdbus_pool_slice_free(slice);
	return ret;
}
