/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni
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
#include "handle.h"
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

	WARN_ON(!list_empty(&bus->monitors_list));
	WARN_ON(!hash_empty(bus->conn_hash));

	kdbus_notify_free(bus);

	kdbus_user_unref(bus->creator);
	kdbus_name_registry_free(bus->name_registry);
	kdbus_domain_unref(bus->domain);
	kdbus_policy_db_clear(&bus->policy_db);
	kdbus_meta_proc_unref(bus->creator_meta);
	kfree(bus);
}

static void kdbus_bus_release(struct kdbus_node *node, bool was_active)
{
	struct kdbus_bus *bus = container_of(node, struct kdbus_bus, node);

	if (was_active)
		atomic_dec(&bus->creator->buses);
}

static struct kdbus_bus *kdbus_bus_new(struct kdbus_domain *domain,
				       const char *name,
				       struct kdbus_bloom_parameter *bloom,
				       const u64 *pattach_owner,
				       const u64 *pattach_recv,
				       u64 flags, kuid_t uid, kgid_t gid)
{
	struct kdbus_bus *b;
	u64 attach_owner;
	u64 attach_recv;
	int ret;

	if (bloom->size < 8 || bloom->size > KDBUS_BUS_BLOOM_MAX_SIZE ||
	    !KDBUS_IS_ALIGNED8(bloom->size) || bloom->n_hash < 1)
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

	if (flags & (KDBUS_MAKE_ACCESS_GROUP | KDBUS_MAKE_ACCESS_WORLD))
		b->node.mode |= S_IRGRP | S_IXGRP;
	if (flags & KDBUS_MAKE_ACCESS_WORLD)
		b->node.mode |= S_IROTH | S_IXOTH;

	b->id = atomic64_inc_return(&domain->last_id);
	b->bus_flags = flags;
	b->attach_flags_req = attach_recv;
	b->attach_flags_owner = attach_owner;
	generate_random_uuid(b->id128);
	b->bloom = *bloom;
	b->domain = kdbus_domain_ref(domain);

	kdbus_policy_db_init(&b->policy_db);

	init_rwsem(&b->conn_rwlock);
	hash_init(b->conn_hash);
	INIT_LIST_HEAD(&b->monitors_list);

	INIT_LIST_HEAD(&b->notify_list);
	spin_lock_init(&b->notify_lock);
	mutex_init(&b->notify_flush_lock);

	ret = kdbus_node_link(&b->node, &domain->node, name);
	if (ret < 0)
		goto exit_unref;

	/* cache the metadata/credentials of the creator */
	b->creator_meta = kdbus_meta_proc_new();
	if (IS_ERR(b->creator_meta)) {
		ret = PTR_ERR(b->creator_meta);
		b->creator_meta = NULL;
		goto exit_unref;
	}

	ret = kdbus_meta_proc_collect(b->creator_meta,
				      KDBUS_ATTACH_CREDS |
				      KDBUS_ATTACH_PIDS |
				      KDBUS_ATTACH_AUXGROUPS |
				      KDBUS_ATTACH_TID_COMM |
				      KDBUS_ATTACH_PID_COMM |
				      KDBUS_ATTACH_EXE |
				      KDBUS_ATTACH_CMDLINE |
				      KDBUS_ATTACH_CGROUP |
				      KDBUS_ATTACH_CAPS |
				      KDBUS_ATTACH_SECLABEL |
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
	b->creator = kdbus_user_lookup(domain, current_uid());
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
 *
 * The caller must hold the name-registry lock of @bus.
 */
void kdbus_bus_broadcast(struct kdbus_bus *bus,
			 struct kdbus_conn *conn_src,
			 struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst;
	unsigned int i;
	int ret;

	lockdep_assert_held(&bus->name_registry->rwlock);

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
			if (!kdbus_conn_policy_talk(conn_dst, NULL, conn_src))
				continue;

			attach_flags = kdbus_meta_calc_attach_flags(conn_src,
								    conn_dst);

			/*
			 * Keep sending messages even if we cannot acquire the
			 * requested metadata. It's up to the receiver to drop
			 * messages that lack expected metadata.
			 */
			if (!conn_src->faked_meta)
				kdbus_meta_proc_collect(kmsg->proc_meta,
							attach_flags);
			kdbus_meta_conn_collect(kmsg->conn_meta, kmsg, conn_src,
						attach_flags);
		} else {
			/*
			 * Check if there is a policy db that prevents the
			 * destination connection from receiving this kernel
			 * notification
			 */
			if (!kdbus_conn_policy_see_notification(conn_dst, NULL,
								kmsg))
				continue;
		}

		ret = kdbus_conn_entry_insert(conn_src, conn_dst, kmsg, NULL);
		if (ret < 0)
			kdbus_conn_lost_message(conn_dst);
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
 *
 * The caller must hold the name-registry lock of @bus.
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

	lockdep_assert_held(&bus->name_registry->rwlock);

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
			if (!conn_src->faked_meta)
				kdbus_meta_proc_collect(kmsg->proc_meta,
							attach_flags);
			kdbus_meta_conn_collect(kmsg->conn_meta, kmsg, conn_src,
						attach_flags);
		}

		ret = kdbus_conn_entry_insert(conn_src, conn_dst, kmsg, NULL);
		if (ret < 0)
			kdbus_conn_lost_message(conn_dst);
	}
	up_read(&bus->conn_rwlock);
}

/**
 * kdbus_cmd_bus_make() - handle KDBUS_CMD_BUS_MAKE
 * @domain:		domain to operate on
 * @argp:		command payload
 *
 * Return: Newly created bus on success, ERR_PTR on failure.
 */
struct kdbus_bus *kdbus_cmd_bus_make(struct kdbus_domain *domain,
				     void __user *argp)
{
	struct kdbus_bus *bus = NULL;
	struct kdbus_cmd *cmd;
	struct kdbus_ep *ep = NULL;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_MAKE_NAME, .mandatory = true },
		{ .type = KDBUS_ITEM_BLOOM_PARAMETER, .mandatory = true },
		{ .type = KDBUS_ITEM_ATTACH_FLAGS_SEND },
		{ .type = KDBUS_ITEM_ATTACH_FLAGS_RECV },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_MAKE_ACCESS_GROUP |
				 KDBUS_MAKE_ACCESS_WORLD,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0)
		return NULL;

	bus = kdbus_bus_new(domain,
			    argv[1].item->str, &argv[2].item->bloom_parameter,
			    argv[3].item ? argv[3].item->data64 : NULL,
			    argv[4].item ? argv[4].item->data64 : NULL,
			    cmd->flags, current_euid(), current_egid());
	if (IS_ERR(bus)) {
		ret = PTR_ERR(bus);
		bus = NULL;
		goto exit;
	}

	if (atomic_inc_return(&bus->creator->buses) > KDBUS_USER_MAX_BUSES) {
		atomic_dec(&bus->creator->buses);
		ret = -EMFILE;
		goto exit;
	}

	if (!kdbus_node_activate(&bus->node)) {
		atomic_dec(&bus->creator->buses);
		ret = -ESHUTDOWN;
		goto exit;
	}

	ep = kdbus_ep_new(bus, "bus", cmd->flags, bus->node.uid, bus->node.gid,
			  false);
	if (IS_ERR(ep)) {
		ret = PTR_ERR(ep);
		ep = NULL;
		goto exit;
	}

	if (!kdbus_node_activate(&ep->node)) {
		ret = -ESHUTDOWN;
		goto exit;
	}

	/*
	 * Drop our own reference, effectively causing the endpoint to be
	 * deactivated and released when the parent bus is.
	 */
	ep = kdbus_ep_unref(ep);

exit:
	ret = kdbus_args_clear(&args, ret);
	if (ret < 0) {
		if (ep) {
			kdbus_node_deactivate(&ep->node);
			kdbus_ep_unref(ep);
		}
		if (bus) {
			kdbus_node_deactivate(&bus->node);
			kdbus_bus_unref(bus);
		}
		return ERR_PTR(ret);
	}
	return bus;
}

/**
 * kdbus_cmd_bus_creator_info() - handle KDBUS_CMD_BUS_CREATOR_INFO
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_cmd_bus_creator_info(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_cmd_info *cmd;
	struct kdbus_bus *bus = conn->ep->bus;
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_item_header item_hdr;
	struct kdbus_info info = {};
	size_t meta_size, name_len;
	struct kvec kvec[5];
	u64 hdr_size = 0;
	u64 attach_flags;
	size_t cnt = 0;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	ret = kdbus_sanitize_attach_flags(cmd->attach_flags, &attach_flags);
	if (ret < 0)
		goto exit;

	attach_flags &= bus->attach_flags_owner;

	ret = kdbus_meta_export_prepare(bus->creator_meta, NULL,
					&attach_flags, &meta_size);
	if (ret < 0)
		goto exit;

	name_len = strlen(bus->node.name) + 1;
	info.id = bus->id;
	info.flags = bus->bus_flags;
	item_hdr.type = KDBUS_ITEM_MAKE_NAME;
	item_hdr.size = KDBUS_ITEM_HEADER_SIZE + name_len;

	kdbus_kvec_set(&kvec[cnt++], &info, sizeof(info), &hdr_size);
	kdbus_kvec_set(&kvec[cnt++], &item_hdr, sizeof(item_hdr), &hdr_size);
	kdbus_kvec_set(&kvec[cnt++], bus->node.name, name_len, &hdr_size);
	cnt += !!kdbus_kvec_pad(&kvec[cnt], &hdr_size);

	slice = kdbus_pool_slice_alloc(conn->pool, hdr_size + meta_size, false);
	if (IS_ERR(slice)) {
		ret = PTR_ERR(slice);
		slice = NULL;
		goto exit;
	}

	ret = kdbus_meta_export(bus->creator_meta, NULL, attach_flags,
				slice, hdr_size, &meta_size);
	if (ret < 0)
		goto exit;

	info.size = hdr_size + meta_size;

	ret = kdbus_pool_slice_copy_kvec(slice, 0, kvec, cnt, hdr_size);
	if (ret < 0)
		goto exit;

	kdbus_pool_slice_publish(slice, &cmd->offset, &cmd->info_size);

	if (kdbus_member_set_user(&cmd->offset, argp, typeof(*cmd), offset) ||
	    kdbus_member_set_user(&cmd->info_size, argp,
				  typeof(*cmd), info_size))
		ret = -EFAULT;

exit:
	kdbus_pool_slice_release(slice);

	return kdbus_args_clear(&args, ret);
}
