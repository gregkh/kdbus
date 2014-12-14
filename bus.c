/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 * Copyright (C) 2014 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "bus.h"
#include "notify.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "item.h"
#include "match.h"
#include "message.h"
#include "metadata.h"
#include "names.h"
#include "policy.h"
#include "util.h"

static void kdbus_bus_free(struct kdbus_node *node)
{
	struct kdbus_bus *bus = container_of(node, struct kdbus_bus, node);

	BUG_ON(!list_empty(&bus->monitors_list));
	BUG_ON(!hash_empty(bus->conn_hash));

	kdbus_notify_free(bus);

	kdbus_domain_user_unref(bus->creator);
	kdbus_name_registry_free(bus->name_registry);
	kdbus_domain_unref(bus->domain);
	kdbus_policy_db_clear(&bus->policy_db);
	kdbus_meta_unref(bus->meta);
	kfree(bus);
}

static void kdbus_bus_release(struct kdbus_node *node, bool was_active)
{
	struct kdbus_bus *bus = container_of(node, struct kdbus_bus, node);

	if (was_active)
		atomic_dec(&bus->creator->buses);
}

/**
 * kdbus_bus_new() - create a kdbus_cmd_make from user-supplied data
 * @domain:		The domain to work on
 * @make:		Information as passed in by userspace
 * @uid:		The uid of the bus node
 * @gid:		The gid of the bus node
 *
 * This function is part of the connection ioctl() interface and will parse
 * the user-supplied data in order to create a new kdbus_bus.
 *
 * Return: the new bus on success, ERR_PTR on failure.
 */
struct kdbus_bus *kdbus_bus_new(struct kdbus_domain *domain,
				const struct kdbus_cmd_make *make,
				kuid_t uid, kgid_t gid)
{
	const struct kdbus_bloom_parameter *bloom = NULL;
	const u64 *pattach_owner = NULL;
	const u64 *pattach_recv = NULL;
	const struct kdbus_item *item;
	const char *name = NULL;
	struct kdbus_bus *b;
	u64 attach_owner;
	u64 attach_recv;
	int ret;

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

		case KDBUS_ITEM_ATTACH_FLAGS_SEND:
			if (pattach_owner)
				return ERR_PTR(-EEXIST);

			pattach_owner = &item->data64[0];
			break;

		case KDBUS_ITEM_ATTACH_FLAGS_RECV:
			if (pattach_recv)
				return ERR_PTR(-EEXIST);

			pattach_recv = &item->data64[0];
			break;

		default:
			return ERR_PTR(-EINVAL);
		}
	}

	if (!name || !bloom)
		return ERR_PTR(-EBADMSG);

	if (bloom->size < 8 || bloom->size > KDBUS_BUS_BLOOM_MAX_SIZE)
		return ERR_PTR(-EINVAL);
	if (!KDBUS_IS_ALIGNED8(bloom->size))
		return ERR_PTR(-EINVAL);
	if (bloom->n_hash < 1)
		return ERR_PTR(-EINVAL);

	ret = kdbus_sanitize_attach_flags(pattach_recv ? *pattach_recv : 0,
					  &attach_recv);
	if (ret < 0)
		return ERR_PTR(ret);

	ret = kdbus_sanitize_attach_flags(pattach_owner ? *pattach_owner : 0,
					  &attach_owner);
	if (ret < 0)
		return ERR_PTR(ret);

	ret = kdbus_verify_uid_prefix(name, domain->user_namespace, uid);
	if (ret < 0)
		return ERR_PTR(ret);

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return ERR_PTR(-ENOMEM);

	kdbus_node_init(&b->node, KDBUS_NODE_BUS);

	b->node.free_cb = kdbus_bus_free;
	b->node.release_cb = kdbus_bus_release;
	b->node.uid = uid;
	b->node.gid = gid;
	b->node.mode = S_IRUSR | S_IXUSR;

	b->access = make->flags & (KDBUS_MAKE_ACCESS_WORLD |
				   KDBUS_MAKE_ACCESS_GROUP);
	if (b->access & (KDBUS_MAKE_ACCESS_GROUP | KDBUS_MAKE_ACCESS_WORLD))
		b->node.mode |= S_IRGRP | S_IXGRP;
	if (b->access & KDBUS_MAKE_ACCESS_WORLD)
		b->node.mode |= S_IROTH | S_IXOTH;

	b->bus_flags = make->flags;
	b->bloom = *bloom;
	b->attach_flags_req = attach_recv;
	b->attach_flags_owner = attach_owner;
	mutex_init(&b->lock);
	init_rwsem(&b->conn_rwlock);
	hash_init(b->conn_hash);
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

	ret = kdbus_node_link(&b->node, &domain->node, name);
	if (ret < 0)
		goto exit_unref;

	/* cache the metadata/credentials of the creator */
	b->meta = kdbus_meta_new();
	if (IS_ERR(b->meta)) {
		ret = PTR_ERR(b->meta);
		b->meta = NULL;
		goto exit_unref;
	}

	ret = kdbus_meta_add_current(b->meta, 0,
				     KDBUS_ATTACH_CREDS		|
				     KDBUS_ATTACH_PIDS		|
				     KDBUS_ATTACH_AUXGROUPS	|
				     KDBUS_ATTACH_TID_COMM	|
				     KDBUS_ATTACH_PID_COMM	|
				     KDBUS_ATTACH_EXE		|
				     KDBUS_ATTACH_CMDLINE	|
				     KDBUS_ATTACH_CGROUP	|
				     KDBUS_ATTACH_CAPS		|
				     KDBUS_ATTACH_SECLABEL	|
				     KDBUS_ATTACH_AUDIT);
	if (ret < 0)
		goto exit_unref;

	b->name_registry = kdbus_name_registry_new();
	if (IS_ERR(b->name_registry)) {
		ret = PTR_ERR(b->name_registry);
		b->name_registry = NULL;
		goto exit_unref;
	}

	/*
	 * Bus-limits of the creator are accounted on its real UID, just like
	 * all other per-user limits.
	 */
	b->creator = kdbus_domain_get_user(domain, current_uid());
	if (IS_ERR(b->creator)) {
		ret = PTR_ERR(b->creator);
		b->creator = NULL;
		goto exit_unref;
	}

	return b;

exit_unref:
	kdbus_node_deactivate(&b->node);
	kdbus_node_unref(&b->node);
	return ERR_PTR(ret);
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
	if (bus)
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
	struct kdbus_ep *ep;
	int ret;

	if (atomic_inc_return(&bus->creator->buses) > KDBUS_USER_MAX_BUSES) {
		atomic_dec(&bus->creator->buses);
		return -EMFILE;
	}

	/*
	 * kdbus_bus_activate() must not be called multiple times, so if
	 * kdbus_node_activate() didn't activate the node, it must already be
	 * dead.
	 */
	if (!kdbus_node_activate(&bus->node)) {
		atomic_dec(&bus->creator->buses);
		return -ESHUTDOWN;
	}

	/*
	 * Create a new default endpoint for this bus. If activation succeeds,
	 * we drop our own reference, effectively causing the endpoint to be
	 * deactivated and released when the parent domain is.
	 */
	ep = kdbus_ep_new(bus, "bus", bus->access,
			  bus->node.uid, bus->node.gid, false);
	if (IS_ERR(ep))
		return PTR_ERR(ep);

	ret = kdbus_ep_activate(ep);
	if (ret < 0)
		kdbus_ep_deactivate(ep);
	kdbus_ep_unref(ep);

	return 0;
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
 * kdbus_bus_broadcast() - send a message to all subscribed connections
 * @bus:	The bus the connections are connected to
 * @conn_src:	The source connection, may be %NULL for kernel notifications
 * @kmsg:	The message to send.
 *
 * Send @kmsg to all connections that are currently active on the bus.
 * Connections must still have matches installed in order to let the message
 * pass.
 */
void kdbus_bus_broadcast(struct kdbus_bus *bus,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst;
	unsigned int i;
	int ret;

	/*
	 * Make sure broadcast are queued on monitors before we send it out to
	 * anyone else. Otherwise, connections might react to broadcasts before
	 * the monitor gets the broadcast queued. In the worst case, the
	 * monitor sees a reaction to the broadcast before the broadcast itself.
	 * We don't give ordering guarantees across connections (and monitors
	 * can re-construct order via sequence numbers), but we should at least
	 * try to avoid re-ordering for monitors.
	 */
	kdbus_bus_eavesdrop(bus, conn_src, kmsg);

	down_read(&bus->conn_rwlock);

	hash_for_each(bus->conn_hash, i, conn_dst, hentry) {
		if (conn_dst->id == kmsg->msg.src_id)
			continue;
		if (!kdbus_conn_is_ordinary(conn_dst))
			continue;

		/*
		 * Check if there is a match for the kmsg object in
		 * the destination connection match db
		 */
		if (!kdbus_match_db_match_kmsg(conn_dst->match_db, conn_src,
					       kmsg))
			continue;

		if (conn_src) {
			u64 attach_flags;

			/*
			 * Anyone can send broadcasts, as they have no
			 * destination. But a receiver needs TALK access to
			 * the sender in order to receive broadcasts.
			 */
			ret = kdbus_ep_policy_check_talk_access(conn_dst->ep,
								conn_dst,
								conn_src);
			if (ret < 0)
				continue;

			attach_flags = kdbus_meta_calc_attach_flags(conn_src,
								    conn_dst);

			/*
			 * Keep sending messages even if we cannot acquire the
			 * requested metadata. It's up to the receiver to drop
			 * messages that lack expected metadata.
			 */
			kdbus_meta_add_current(kmsg->meta, kmsg->seq,
					       attach_flags);
			kdbus_meta_add_conn_info(kmsg->meta,
						 conn_src, attach_flags);
		} else {
			/*
			 * Check if there is a policy db that prevents the
			 * destination connection from receiving this kernel
			 * notification
			 */
			ret = kdbus_ep_policy_check_notification(conn_dst->ep,
								 conn_dst,
								 kmsg);
			if (ret < 0)
				continue;
		}

		ret = kdbus_conn_entry_insert(conn_src, conn_dst, kmsg, NULL);
		if (ret < 0)
			atomic_inc(&conn_dst->lost_count);
	}

	up_read(&bus->conn_rwlock);
}

/**
 * kdbus_bus_eavesdrop() - send a message to all subscribed monitors
 * @bus:	The bus the monitors are connected to
 * @conn_src:	The source connection, may be %NULL for kernel notifications
 * @kmsg:	The message to send.
 *
 * Send @kmsg to all monitors that are currently active on the bus. Monitors
 * must still have matches installed in order to let the message pass.
 */
void kdbus_bus_eavesdrop(struct kdbus_bus *bus,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst;
	int ret;

	/*
	 * Monitor connections get all messages; ignore possible errors
	 * when sending messages to monitor connections.
	 */

	down_read(&bus->conn_rwlock);
	list_for_each_entry(conn_dst, &bus->monitors_list, monitor_entry) {
		/*
		 * Collect metadata requested by the destination connection.
		 * Ignore errors, as receivers need to check metadata
		 * availability, anyway. So it's still better to send messages
		 * that lack data, than to skip it entirely.
		 */
		if (conn_src) {
			u64 attach_flags;

			attach_flags = kdbus_meta_calc_attach_flags(conn_src,
								    conn_dst);
			kdbus_meta_add_current(kmsg->meta, kmsg->seq,
					       attach_flags);
			kdbus_meta_add_conn_info(kmsg->meta,
						 conn_src, attach_flags);
		}

		ret = kdbus_conn_entry_insert(conn_src, conn_dst, kmsg, NULL);
		if (ret < 0)
			atomic_inc(&conn_dst->lost_count);
	}
	up_read(&bus->conn_rwlock);
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
	struct kdbus_bus *bus = conn->ep->bus;
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_item *meta_items;
	struct kdbus_info info = {};
	struct kdbus_item item = {};
	size_t meta_size, name_len;
	struct kvec kvec[5];
	u64 attach_flags;
	size_t cnt = 0;
	int ret;

	info.id = bus->id;
	info.flags = bus->bus_flags;

	name_len = strlen(bus->node.name) + 1;

	/* mask out what information the bus owner wants to pass us */
	attach_flags = cmd_info->flags & bus->attach_flags_owner;

	meta_items = kdbus_meta_export(bus->meta, attach_flags, &meta_size);
	if (IS_ERR(meta_items))
		return PTR_ERR(meta_items);

	item.type = KDBUS_ITEM_MAKE_NAME;
	item.size = KDBUS_ITEM_HEADER_SIZE + name_len;

	kdbus_kvec_set(&kvec[cnt++], &info, sizeof(info), &info.size);
	kdbus_kvec_set(&kvec[cnt++], &item, KDBUS_ITEM_HEADER_SIZE, &info.size);
	kdbus_kvec_set(&kvec[cnt++], bus->node.name, name_len, &info.size);
	cnt += !!kdbus_kvec_pad(&kvec[cnt], &info.size);

	if (meta_items && meta_size)
		kdbus_kvec_set(&kvec[cnt++], meta_items, meta_size, &info.size);

	slice = kdbus_pool_slice_alloc(conn->pool, info.size, kvec, NULL, cnt);
	if (IS_ERR(slice)) {
		ret = PTR_ERR(slice);
		slice = NULL;
		goto exit;
	}

	/* write back the offset */
	kdbus_pool_slice_publish(slice, &cmd_info->offset,
				 &cmd_info->info_size);
	ret = 0;

	kdbus_pool_slice_release(slice);
exit:
	kfree(meta_items);
	return ret;
}
