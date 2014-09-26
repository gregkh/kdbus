/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
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
#include <linux/idr.h>
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
#include "names.h"
#include "policy.h"

/**
 * kdbus_bus_cred_is_privileged() - check whether the given credentials in
 *				    combination with the capabilities of the
 *				    current thead are privileged on the bus
 * @bus:		The bus to check
 * @cred:		The credentials to match
 *
 * Return: true if the credentials are privileged, otherwise false.
 */
bool kdbus_bus_cred_is_privileged(const struct kdbus_bus *bus,
				  const struct cred *cred)
{
	/* Capabilities are *ALWAYS* tested against the current thread, they're
	 * never remembered from conn-credentials. */
	if (ns_capable(&init_user_ns, CAP_IPC_OWNER))
		return true;

	return uid_eq(bus->uid_owner, cred->fsuid);
}

/**
 * kdbus_bus_uid_is_privileged() - check whether the current user is a
 *				   priviledged bus user
 * @bus:		The bus to check
 *
 * Return: true if the current user has CAP_IPC_OWNER capabilities, or
 * if it has the same UID as the user that created the bus. Otherwise,
 * false is returned.
 */
bool kdbus_bus_uid_is_privileged(const struct kdbus_bus *bus)
{
	return kdbus_bus_cred_is_privileged(bus, current_cred());
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
	kref_get(&bus->kref);
	return bus;
}

static void __kdbus_bus_free(struct kref *kref)
{
	struct kdbus_bus *bus = container_of(kref, struct kdbus_bus, kref);

	BUG_ON(!bus->disconnected);
	BUG_ON(!list_empty(&bus->ep_list));
	BUG_ON(!list_empty(&bus->monitors_list));
	BUG_ON(!hash_empty(bus->conn_hash));

	kdbus_notify_free(bus);
	atomic_dec(&bus->user->buses);
	kdbus_domain_user_unref(bus->user);
	kdbus_name_registry_free(bus->name_registry);
	kdbus_domain_unref(bus->domain);
	kdbus_policy_db_clear(&bus->policy_db);
	kfree(bus->name);
	kfree(bus);
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

	kref_put(&bus->kref, __kdbus_bus_free);
	return NULL;
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

	mutex_lock(&bus->lock);
	hash_for_each_possible(bus->conn_hash, conn, hentry, id)
		if (conn->id == id) {
			found = kdbus_conn_ref(conn);
			break;
		}
	mutex_unlock(&bus->lock);

	return found;
}

/**
 * kdbus_bus_disconnect() - disconnect a bus
 * @bus:		The kdbus reference
 *
 * The passed bus will be disconnected and the associated endpoint will be
 * unref'ed.
 */
void kdbus_bus_disconnect(struct kdbus_bus *bus)
{
	mutex_lock(&bus->lock);
	if (bus->disconnected) {
		mutex_unlock(&bus->lock);
		return;
	}
	bus->disconnected = true;
	mutex_unlock(&bus->lock);

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

		kdbus_ep_disconnect(ep);
		kdbus_ep_unref(ep);
	}

	/* drop reference for our "bus" endpoint after we disconnected */
	bus->ep = kdbus_ep_unref(bus->ep);
}

static struct kdbus_bus *kdbus_bus_find(struct kdbus_domain *domain,
					const char *name)
{
	struct kdbus_bus *bus = NULL;
	struct kdbus_bus *b;

	mutex_lock(&domain->lock);
	list_for_each_entry(b, &domain->bus_list, domain_entry) {
		if (strcmp(b->name, name))
			continue;

		bus = kdbus_bus_ref(b);
		break;
	}
	mutex_unlock(&domain->lock);

	return bus;
}

/**
 * kdbus_bus_new() - create a new bus
 * @domain:			The domain to work on
 * @make:		Pointer to a struct kdbus_cmd_make containing the
 *			details for the bus creation
 * @name:		Name of the bus
 * @bloom:		Bloom parameters for this bus
 * @mode:		The access mode for the device node
 * @uid:		The uid of the device node
 * @gid:		The gid of the device node
 * @bus:		Pointer to a reference where the new bus is stored
 *
 * This function will allocate a new kdbus_bus and link it to the given
 * domain.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_bus_new(struct kdbus_domain *domain,
		  const struct kdbus_cmd_make *make,
		  const char *name,
		  const struct kdbus_bloom_parameter *bloom,
		  umode_t mode, kuid_t uid, kgid_t gid,
		  struct kdbus_bus **bus)
{
	struct kdbus_bus *b;
	char prefix[16];
	int ret;

	BUG_ON(*bus);

	/* enforce "$UID-" prefix */
	snprintf(prefix, sizeof(prefix), "%u-",
		 from_kuid(current_user_ns(), uid));
	if (strncmp(name, prefix, strlen(prefix) != 0))
		return -EINVAL;

	b = kdbus_bus_find(domain, name);
	if (b) {
		kdbus_bus_unref(b);
		return -EEXIST;
	}

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	kref_init(&b->kref);
	b->uid_owner = uid;
	b->bus_flags = make->flags;
	b->bloom = *bloom;
	mutex_init(&b->lock);
	hash_init(b->conn_hash);
	INIT_LIST_HEAD(&b->ep_list);
	INIT_LIST_HEAD(&b->monitors_list);
	INIT_LIST_HEAD(&b->notify_list);
	spin_lock_init(&b->notify_lock);
	mutex_init(&b->notify_flush_lock);
	atomic64_set(&b->conn_seq_last, 0);
	b->domain = kdbus_domain_ref(domain);
	kdbus_policy_db_init(&b->policy_db);

	/* generate unique bus id */
	generate_random_uuid(b->id128);

	b->name = kstrdup(name, GFP_KERNEL);
	if (!b->name) {
		ret = -ENOMEM;
		goto exit_free;
	}

	ret = kdbus_name_registry_new(&b->name_registry);
	if (ret < 0)
		goto exit_free_name;

	ret = kdbus_ep_new(b, "bus", mode, uid, gid,
			   !(make->flags & KDBUS_MAKE_POLICY_OPEN), &b->ep);
	if (ret < 0)
		goto exit_free_reg;

	/* link into domain */
	mutex_lock(&domain->lock);
	if (domain->disconnected) {
		ret = -ESHUTDOWN;
		goto exit_unref_user_unlock;
	}

	/* account the bus against the user */
	ret = kdbus_domain_get_user_unlocked(domain, uid, &b->user);
	if (ret < 0)
		goto exit_unref_user_unlock;

	if (!capable(CAP_IPC_OWNER) &&
	    atomic_inc_return(&b->user->buses) > KDBUS_USER_MAX_BUSES) {
		atomic_dec(&b->user->buses);
		ret = -EMFILE;
		goto exit_unref_user_unlock;
	}

	b->id = ++domain->bus_seq_last;
	list_add_tail(&b->domain_entry, &domain->bus_list);
	mutex_unlock(&domain->lock);

	*bus = b;
	return 0;

exit_unref_user_unlock:
	mutex_unlock(&domain->lock);
	kdbus_domain_user_unref(b->user);
	kdbus_ep_disconnect(b->ep);
	kdbus_ep_unref(b->ep);
exit_free_reg:
	kdbus_name_registry_free(b->name_registry);
exit_free_name:
	kfree(b->name);
exit_free:
	kdbus_policy_db_clear(&b->policy_db);
	kdbus_domain_unref(b->domain);
	kfree(b);
	return ret;
}

/**
 * kdbus_bus_make_user() - create a kdbus_cmd_make from user-supplied data
 * @make:		Reference to the location where to store the result
 * @name:		Shortcut to the requested name
 * @bloom:		Bloom parameters for this bus
 *
 * This function is part of the connection ioctl() interface and will parse
 * the user-supplied data.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_bus_make_user(const struct kdbus_cmd_make *make,
			char **name, struct kdbus_bloom_parameter *bloom)
{
	const struct kdbus_item *item;
	const char *n = NULL;
	const struct kdbus_bloom_parameter *bl = NULL;
	int ret;

	KDBUS_ITEMS_FOREACH(item, make->items, KDBUS_ITEMS_SIZE(make, items)) {
		size_t payload_size;

		if (!KDBUS_ITEM_VALID(item, &make->items,
				      KDBUS_ITEMS_SIZE(make, items)))
			return -EINVAL;

		payload_size = item->size - KDBUS_ITEM_HEADER_SIZE;

		switch (item->type) {
		case KDBUS_ITEM_MAKE_NAME:
			if (n)
				return -EEXIST;

			ret = kdbus_item_validate_name(item);
			if (ret < 0)
				return ret;

			n = item->str;
			break;

		case KDBUS_ITEM_BLOOM_PARAMETER:
			if (payload_size != sizeof(*bl))
				return -EINVAL;

			bl = &item->bloom_parameter;
			break;
		}
	}

	if (!KDBUS_ITEMS_END(item, make->items, KDBUS_ITEMS_SIZE(make, items)))
		return -EINVAL;

	if (!n || !bl)
		return -EBADMSG;

	if (bl->size < 8 || bl->size > KDBUS_BUS_BLOOM_MAX_SIZE)
		return -EINVAL;
	if (!KDBUS_IS_ALIGNED8(bl->size))
		return -EINVAL;
	if (bl->n_hash < 1)
		return -EINVAL;

	*name = (char *)n;
	*bloom = *bl;
	return 0;
}
