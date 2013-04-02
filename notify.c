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

static int kdbus_msg_reply(struct kdbus_ep *ep,
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

	ret = kdbus_kmsg_send(ep, &kmsg);
	kdbus_kmsg_unref(kmsg);

	return ret;
}

int kdbus_msg_reply_timeout(struct kdbus_ep *ep,
			    const struct kdbus_msg *orig_msg)
{
	return kdbus_msg_reply(ep, orig_msg, KDBUS_MSG_REPLY_TIMEOUT);
}

int kdbus_msg_reply_dead(struct kdbus_ep *ep,
			 const struct kdbus_msg *orig_msg)
{
	return kdbus_msg_reply(ep, orig_msg, KDBUS_MSG_REPLY_DEAD);
}

