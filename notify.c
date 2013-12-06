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

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/poll.h>

#include "notify.h"
#include "bus.h"
#include "endpoint.h"
#include "message.h"
#include "connection.h"

static int kdbus_notify_reply(struct kdbus_ep *ep, u64 src_id,
			      u64 cookie, u64 msg_type)
{
	struct kdbus_conn *dst_conn;
	struct kdbus_kmsg *kmsg;
	struct kdbus_item *item;
	int ret;

	mutex_lock(&ep->bus->lock);
	dst_conn = kdbus_bus_find_conn_by_id(ep->bus, src_id);
	mutex_unlock(&ep->bus->lock);

	if (!dst_conn)
		return -ENXIO;

	ret = kdbus_kmsg_new(KDBUS_PART_SIZE(0), &kmsg);
	if (ret < 0)
		goto exit_unref_conn;

	/*
	 * a kernel-generated notification can only contain one
	 * struct kdbus_item, so make a shortcut here for
	 * faster lookup in the match db.
	 */
	kmsg->notification_type = msg_type;

	kmsg->msg.dst_id = src_id;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;
	kmsg->msg.payload_type = KDBUS_PAYLOAD_KERNEL;
	kmsg->msg.cookie_reply = cookie;

	item = kmsg->msg.items;
	item->type = msg_type;

	ret = kdbus_conn_kmsg_send(ep, NULL, kmsg);
	kdbus_kmsg_free(kmsg);

exit_unref_conn:
	kdbus_conn_unref(dst_conn);

	return ret;
}

/**
 * kdbus_notify_reply_timeout - send a timeout reply
 * @ep:			The endpoint to use for sending
 * @src_id:		The id to use as sender address
 * @cookie		The cookie to set in the reply.
 *
 * Sends a message that has a KDBUS_ITEM_REPLY_TIMEOUT item attached.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_notify_reply_timeout(struct kdbus_ep *ep, u64 src_id, u64 cookie)
{
	return kdbus_notify_reply(ep, src_id, cookie, KDBUS_ITEM_REPLY_TIMEOUT);
}

/**
 * kdbus_notify_reply_dead - send a 'dead' reply
 * @ep:			The endpoint to use for sending
 * @src_id:		The id to use as sender address
 * @cookie		The cookie to set in the reply.
 *
 * Sends a message that has a KDBUS_ITEM_REPLY_DEAD item attached.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_notify_reply_dead(struct kdbus_ep *ep, u64 src_id, u64 cookie)
{
	return kdbus_notify_reply(ep, src_id, cookie, KDBUS_ITEM_REPLY_DEAD);
}

/**
 * kdbus_notify_name_change - send a notification about a name owner change
 * @ep:			The endpoint to use for sending
 * @type:		The type if the notification; KDBUS_ITEM_NAME_ADD,
 * 			KDBUS_ITEM_NAME_CHANGE or KDBUS_ITEM_NAME_REMOVE
 * @old_id:		The id of the connection that used to own the name
 * @new_id:		The id of the new owner connection
 * @flags:		The flags to pass in the KDBUS_ITEM flags field
 * @name:		The name that was removed or assigned to a new owner
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_notify_name_change(struct kdbus_ep *ep, u64 type,
			     u64 old_id, u64 new_id, u64 flags,
			     const char *name)
{
	struct kdbus_notify_name_change *name_change;
	struct kdbus_kmsg *kmsg = NULL;
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	size_t extra_size;
	int ret;

	extra_size = sizeof(*name_change) + strlen(name);
	ret = kdbus_kmsg_new(extra_size, &kmsg);
	if (ret < 0)
		return ret;

	kmsg->notification_type = type;
	msg = &kmsg->msg;
	item = msg->items;
	name_change = (struct kdbus_notify_name_change *)item->data;

	msg->dst_id = KDBUS_DST_ID_BROADCAST;
	msg->src_id = KDBUS_SRC_ID_KERNEL;

	item->type = type;

	name_change->old_id = old_id;
	name_change->new_id = new_id;
	name_change->flags = flags;
	strcpy(name_change->name, name);

	ret = kdbus_conn_kmsg_send(ep, NULL, kmsg);
	kdbus_kmsg_free(kmsg);

	return ret;
}

/**
 * kdbus_notify_id_change - send a notification about a unique ID change
 * @ep:			The endpoint to use for sending
 * @type:		The type if the notification; KDBUS_MATCH_ID_ADD or
 * 			KDBUS_MATCH_ID_REMOVE
 * @id:			The id of the connection that was added or removed
 * @flags:		The flags to pass in the KDBUS_ITEM flags field
 *
 * Returns: 0 on success, negative errno on failure.
 */
int kdbus_notify_id_change(struct kdbus_ep *ep, u64 type,
			   u64 id, u64 flags)
{
	struct kdbus_notify_id_change *id_change;
	struct kdbus_kmsg *kmsg = NULL;
	struct kdbus_item *item;
	struct kdbus_msg *msg;
	int ret;

	ret = kdbus_kmsg_new(sizeof(*id_change), &kmsg);
	if (ret < 0)
		return ret;

	kmsg->notification_type = type;
	msg = &kmsg->msg;
	item = msg->items;
	id_change = (struct kdbus_notify_id_change *)item->data;

	msg->dst_id = KDBUS_DST_ID_BROADCAST;
	msg->src_id = KDBUS_SRC_ID_KERNEL;

	item->type = type;

	id_change->id = id;
	id_change->flags = flags;

	ret = kdbus_conn_kmsg_send(ep, NULL, kmsg);
	kdbus_kmsg_free(kmsg);

	return ret;
}
