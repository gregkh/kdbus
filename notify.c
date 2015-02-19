/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "item.h"
#include "message.h"
#include "notify.h"

static inline void kdbus_notify_add_tail(struct kdbus_kmsg *kmsg,
					 struct kdbus_bus *bus)
{
	spin_lock(&bus->notify_lock);
	list_add_tail(&kmsg->notify_entry, &bus->notify_list);
	spin_unlock(&bus->notify_lock);
}

static int kdbus_notify_reply(struct kdbus_bus *bus, u64 id,
			      u64 cookie, u64 msg_type)
{
	struct kdbus_kmsg *kmsg = NULL;

	WARN_ON(id == 0);

	kmsg = kdbus_kmsg_new(bus, 0);
	if (IS_ERR(kmsg))
		return PTR_ERR(kmsg);

	/*
	 * a kernel-generated notification can only contain one
	 * struct kdbus_item, so make a shortcut here for
	 * faster lookup in the match db.
	 */
	kmsg->notify_type = msg_type;
	kmsg->msg.flags = KDBUS_MSG_SIGNAL;
	kmsg->msg.dst_id = id;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;
	kmsg->msg.payload_type = KDBUS_PAYLOAD_KERNEL;
	kmsg->msg.cookie_reply = cookie;
	kmsg->msg.items[0].type = msg_type;

	kdbus_notify_add_tail(kmsg, bus);

	return 0;
}

/**
 * kdbus_notify_reply_timeout() - queue a timeout reply
 * @bus:		Bus which queues the messages
 * @id:			The destination's connection ID
 * @cookie:		The cookie to set in the reply.
 *
 * Queues a message that has a KDBUS_ITEM_REPLY_TIMEOUT item attached.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_reply_timeout(struct kdbus_bus *bus, u64 id, u64 cookie)
{
	return kdbus_notify_reply(bus, id, cookie, KDBUS_ITEM_REPLY_TIMEOUT);
}

/**
 * kdbus_notify_reply_dead() - queue a 'dead' reply
 * @bus:		Bus which queues the messages
 * @id:			The destination's connection ID
 * @cookie:		The cookie to set in the reply.
 *
 * Queues a message that has a KDBUS_ITEM_REPLY_DEAD item attached.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_reply_dead(struct kdbus_bus *bus, u64 id, u64 cookie)
{
	return kdbus_notify_reply(bus, id, cookie, KDBUS_ITEM_REPLY_DEAD);
}

/**
 * kdbus_notify_name_change() - queue a notification about a name owner change
 * @bus:		Bus which queues the messages
 * @type:		The type if the notification; KDBUS_ITEM_NAME_ADD,
 *			KDBUS_ITEM_NAME_CHANGE or KDBUS_ITEM_NAME_REMOVE
 * @old_id:		The id of the connection that used to own the name
 * @new_id:		The id of the new owner connection
 * @old_flags:		The flags to pass in the KDBUS_ITEM flags field for
 *			the old owner
 * @new_flags:		The flags to pass in the KDBUS_ITEM flags field for
 *			the new owner
 * @name:		The name that was removed or assigned to a new owner
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_name_change(struct kdbus_bus *bus, u64 type,
			     u64 old_id, u64 new_id,
			     u64 old_flags, u64 new_flags,
			     const char *name)
{
	struct kdbus_kmsg *kmsg = NULL;
	size_t name_len, extra_size;

	name_len = strlen(name) + 1;
	extra_size = sizeof(struct kdbus_notify_name_change) + name_len;
	kmsg = kdbus_kmsg_new(bus, extra_size);
	if (IS_ERR(kmsg))
		return PTR_ERR(kmsg);

	kmsg->msg.flags = KDBUS_MSG_SIGNAL;
	kmsg->msg.dst_id = KDBUS_DST_ID_BROADCAST;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;
	kmsg->msg.payload_type = KDBUS_PAYLOAD_KERNEL;
	kmsg->notify_type = type;
	kmsg->notify_old_id = old_id;
	kmsg->notify_new_id = new_id;
	kmsg->msg.items[0].type = type;
	kmsg->msg.items[0].name_change.old_id.id = old_id;
	kmsg->msg.items[0].name_change.old_id.flags = old_flags;
	kmsg->msg.items[0].name_change.new_id.id = new_id;
	kmsg->msg.items[0].name_change.new_id.flags = new_flags;
	memcpy(kmsg->msg.items[0].name_change.name, name, name_len);
	kmsg->notify_name = kmsg->msg.items[0].name_change.name;

	kdbus_notify_add_tail(kmsg, bus);

	return 0;
}

/**
 * kdbus_notify_id_change() - queue a notification about a unique ID change
 * @bus:		Bus which queues the messages
 * @type:		The type if the notification; KDBUS_ITEM_ID_ADD or
 *			KDBUS_ITEM_ID_REMOVE
 * @id:			The id of the connection that was added or removed
 * @flags:		The flags to pass in the KDBUS_ITEM flags field
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_id_change(struct kdbus_bus *bus, u64 type, u64 id, u64 flags)
{
	struct kdbus_kmsg *kmsg = NULL;

	kmsg = kdbus_kmsg_new(bus, sizeof(struct kdbus_notify_id_change));
	if (IS_ERR(kmsg))
		return PTR_ERR(kmsg);

	kmsg->msg.flags = KDBUS_MSG_SIGNAL;
	kmsg->msg.dst_id = KDBUS_DST_ID_BROADCAST;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;
	kmsg->msg.payload_type = KDBUS_PAYLOAD_KERNEL;
	kmsg->notify_type = type;

	switch (type) {
	case KDBUS_ITEM_ID_ADD:
		kmsg->notify_new_id = id;
		break;

	case KDBUS_ITEM_ID_REMOVE:
		kmsg->notify_old_id = id;
		break;

	default:
		BUG();
	}

	kmsg->msg.items[0].type = type;
	kmsg->msg.items[0].id_change.id = id;
	kmsg->msg.items[0].id_change.flags = flags;

	kdbus_notify_add_tail(kmsg, bus);

	return 0;
}

/**
 * kdbus_notify_flush() - send a list of collected messages
 * @bus:		Bus which queues the messages
 *
 * The list is empty after sending the messages.
 */
void kdbus_notify_flush(struct kdbus_bus *bus)
{
	LIST_HEAD(notify_list);
	struct kdbus_kmsg *kmsg, *tmp;

	mutex_lock(&bus->notify_flush_lock);
	down_read(&bus->name_registry->rwlock);

	spin_lock(&bus->notify_lock);
	list_splice_init(&bus->notify_list, &notify_list);
	spin_unlock(&bus->notify_lock);

	list_for_each_entry_safe(kmsg, tmp, &notify_list, notify_entry) {
		kdbus_meta_conn_collect(kmsg->conn_meta, kmsg, NULL,
					KDBUS_ATTACH_TIMESTAMP);

		if (kmsg->msg.dst_id != KDBUS_DST_ID_BROADCAST) {
			struct kdbus_conn *conn;

			conn = kdbus_bus_find_conn_by_id(bus, kmsg->msg.dst_id);
			if (conn) {
				kdbus_bus_eavesdrop(bus, NULL, kmsg);
				kdbus_conn_entry_insert(NULL, conn, kmsg, NULL);
				kdbus_conn_unref(conn);
			}
		} else {
			kdbus_bus_broadcast(bus, NULL, kmsg);
		}

		list_del(&kmsg->notify_entry);
		kdbus_kmsg_free(kmsg);
	}

	up_read(&bus->name_registry->rwlock);
	mutex_unlock(&bus->notify_flush_lock);
}

/**
 * kdbus_notify_free() - free a list of collected messages
 * @bus:		Bus which queues the messages
 */
void kdbus_notify_free(struct kdbus_bus *bus)
{
	struct kdbus_kmsg *kmsg, *tmp;

	list_for_each_entry_safe(kmsg, tmp, &bus->notify_list, notify_entry) {
		list_del(&kmsg->notify_entry);
		kdbus_kmsg_free(kmsg);
	}
}
