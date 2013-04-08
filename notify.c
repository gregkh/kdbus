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
#include "kdbus.h"

#include "kdbus_internal.h"

static int kdbus_notify_reply(struct kdbus_ep *ep,
			      const struct kdbus_msg *orig_msg,
			      u64 msg_type)
{
	struct kdbus_conn *dst_conn;
	struct kdbus_kmsg *kmsg;
	struct kdbus_msg_data *data;
	u64 dst_id = orig_msg->src_id;
	int ret;

	dst_conn = kdbus_bus_find_conn_by_id(ep->bus, dst_id);
	if (!dst_conn)
		return -ENOENT;

	ret = kdbus_kmsg_new(0, &kmsg);
	if (ret < 0)
		return ret;

	kmsg->msg.dst_id = dst_id;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;
	kmsg->msg.cookie_reply = orig_msg->cookie;

	data = kmsg->msg.data;
	data->type = msg_type;

	ret = kdbus_kmsg_send(ep, NULL, kmsg);
	kdbus_kmsg_unref(kmsg);

	return ret;
}

int kdbus_notify_reply_timeout(struct kdbus_ep *ep,
			       const struct kdbus_msg *orig_msg)
{
	return kdbus_notify_reply(ep, orig_msg, KDBUS_MSG_REPLY_TIMEOUT);
}

int kdbus_notify_reply_dead(struct kdbus_ep *ep,
			    const struct kdbus_msg *orig_msg)
{
	return kdbus_notify_reply(ep, orig_msg, KDBUS_MSG_REPLY_DEAD);
}

int kdbus_notify_name_change(struct kdbus_ep *ep, u64 type,
			     u64 old_id, u64 new_id, u64 flags,
			     const char *name)
{
	struct kdbus_manager_msg_name_change *name_change;
	struct kdbus_kmsg *kmsg = NULL;
	struct kdbus_msg_data *data;
	struct kdbus_msg *msg;
	u64 extra_size = sizeof(*name_change) + strlen(name);
	int ret;

	ret = kdbus_kmsg_new(extra_size, &kmsg);
	if (ret < 0)
		return ret;

	if (!kmsg)
		return -ENOMEM;

	msg = &kmsg->msg;
	data = msg->data;
	name_change = (struct kdbus_manager_msg_name_change *) data->data;

	/* FIXME */
	msg->dst_id = KDBUS_DST_ID_BROADCAST;
	msg->src_id = KDBUS_SRC_ID_KERNEL;

	data->type = type;

	name_change->old_id = old_id;
	name_change->new_id = new_id;
	name_change->flags = flags;
	strcpy(name_change->name, name);

	ret = kdbus_kmsg_send(ep, NULL, kmsg);
	kdbus_kmsg_unref(kmsg);

	return 0;
}

int kdbus_notify_id_change(struct kdbus_ep *ep, u64 type,
			   u64 id, u64 flags)
{
	struct kdbus_manager_msg_id_change *id_change;
	struct kdbus_kmsg *kmsg = NULL;
	struct kdbus_msg_data *data;
	struct kdbus_msg *msg;
	u64 extra_size = sizeof(*id_change);
	int ret;

	ret = kdbus_kmsg_new(extra_size, &kmsg);
	if (ret < 0)
		return ret;

	if (!kmsg)
		return -ENOMEM;

	msg = &kmsg->msg;
	data = msg->data;
	id_change = (struct kdbus_manager_msg_id_change *) data->data;

	/* FIXME */
	msg->dst_id = KDBUS_DST_ID_BROADCAST;
	msg->src_id = KDBUS_SRC_ID_KERNEL;

	data->type = type;

	id_change->id = id;

	ret = kdbus_kmsg_send(ep, NULL, kmsg);
	kdbus_kmsg_unref(kmsg);

	return 0;
}

