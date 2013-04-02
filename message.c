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

#define KDBUS_MSG_DATA_SIZE(SIZE) \
	ALIGN((SIZE) + offsetof(struct kdbus_msg_data, data), sizeof(u64))

static void __kdbus_kmsg_free(struct kref *kref)
{
	struct kdbus_kmsg *kmsg = container_of(kref, struct kdbus_kmsg, kref);
	kfree(kmsg);
}

void kdbus_kmsg_unref(struct kdbus_kmsg *kmsg)
{
	kref_put(&kmsg->kref, __kdbus_kmsg_free);
}

static struct kdbus_kmsg *kdbus_kmsg_ref(struct kdbus_kmsg *kmsg)
{
	kref_get(&kmsg->kref);
	return kmsg;
}

static void kdbus_kmsg_init(struct kdbus_kmsg *kmsg,
			    struct kdbus_conn *conn)
{
	kmsg->msg.src_id = conn->id;
	kref_init(&kmsg->kref);
}

int kdbus_kmsg_new(struct kdbus_conn *conn, u64 extra_size,
		   struct kdbus_kmsg **m)
{
	u64 size = sizeof(struct kdbus_kmsg) + KDBUS_MSG_DATA_SIZE(extra_size);
	struct kdbus_kmsg *kmsg = kzalloc(size, GFP_KERNEL);

	if (!kmsg)
		return -ENOMEM;

	kdbus_kmsg_init(kmsg, conn);

	kmsg->msg.size = size - offsetof(struct kdbus_kmsg, msg);
	kmsg->msg.data[0].size = KDBUS_MSG_DATA_SIZE(extra_size);

	*m = kmsg;
	return 0;
}

int kdbus_kmsg_new_from_user(struct kdbus_conn *conn, void __user *argp,
			     struct kdbus_kmsg **m)
{
	u64 __user *msgsize = argp + offsetof(struct kdbus_msg, size);
	struct kdbus_kmsg *kmsg;
	u64 size;
	int err;

	if (get_user(size, msgsize))
		err = -EFAULT;

	if (size < sizeof(struct kdbus_msg) || size > 0xffff)
		return -EMSGSIZE;

	size += sizeof(*kmsg) - sizeof(kmsg->msg);

	kmsg = kmalloc(size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;
	if (copy_from_user(&kmsg->msg, argp, size)) {
		err = -EFAULT;
		goto out_err;
	}

	kdbus_kmsg_init(kmsg, conn);

	*m = kmsg;
	return 0;

out_err:
	kfree(m);
	return err;
}

static const struct kdbus_msg_data *kdbus_msg_get_data(struct kdbus_msg *msg,
						       u64 type,
						       int index)
{
	u64 size = msg->size - offsetof(struct kdbus_msg, data);
	const struct kdbus_msg_data *data = msg->data;

	while (size > 0 && size >= data->size) {
		if (data->type == type && index-- == 0)
			return data;

		size -= data->size;
		data = (struct kdbus_msg_data *) (((u8 *) data) + data->size);
	}

	return NULL;
}


static void __maybe_unused kdbus_msg_dump(const struct kdbus_msg *msg)
{
	u64 size = msg->size - offsetof(struct kdbus_msg, data);
	const struct kdbus_msg_data *data = msg->data;

	pr_info("msg size=%llu, flags=0x%llx, dst_id=%llu, src_id=%llu, "
		"cookie=0x%llx payload_type=0x%llx, timeout=%llu\n",
		(unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		(unsigned long long) msg->dst_id,
		(unsigned long long) msg->src_id,
		(unsigned long long) msg->cookie,
		(unsigned long long) msg->payload_type,
		(unsigned long long) msg->timeout);

	while (size > 0 && size >= data->size) {
		pr_info("`- msg_data size=%llu, type=0x%llx\n",
			data->size, data->type);

		size -= data->size;
		data = (struct kdbus_msg_data *) (((u8 *) data) + data->size);
	}
}

static struct kdbus_kmsg __must_check *
kdbus_kmsg_append_data(struct kdbus_kmsg *kmsg,
		       const struct kdbus_msg_data *data)
{
	u64 size = sizeof(*kmsg) - sizeof(kmsg->msg) +
			kmsg->msg.size + data->size;

	kmsg = krealloc(kmsg, size, GFP_KERNEL);
	if (!kmsg)
		return NULL;

	memcpy(((u8 *) &kmsg->msg) + kmsg->msg.size, data, data->size);
	kmsg->msg.size += data->size;

	return kmsg;
}

static struct kdbus_kmsg __must_check *
kdbus_kmsg_append_timestamp(struct kdbus_kmsg *kmsg, u64 *now_ns)
{
	struct kdbus_msg_data *data;
	u64 size = KDBUS_MSG_DATA_SIZE(sizeof(u64));
	struct timespec ts;

	data = kzalloc(size, GFP_KERNEL);
	if (!data)
		return NULL;

	ktime_get_ts(&ts);

	data->size = size;
	data->type = KDBUS_MSG_TIMESTAMP;
	data->data_u64[0] = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
	if (now_ns)
		*now_ns = data->ts_ns;

	kmsg = kdbus_kmsg_append_data(kmsg, data);
	kfree(data);

	return kmsg;
}

static int kdbus_conn_enqueue_kmsg(struct kdbus_conn *conn,
				   struct kdbus_kmsg *kmsg)
{
	struct kdbus_msg_list_entry *entry;

	if (!conn->active)
		return -EAGAIN;

	/* TODO: implement filtering */

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->kmsg = kdbus_kmsg_ref(kmsg);
	INIT_LIST_HEAD(&entry->list);

	mutex_lock(&conn->msg_lock);
	list_add_tail(&entry->list, &conn->msg_list);
	mutex_unlock(&conn->msg_lock);

	wake_up_interruptible(&conn->ep->wait);

	return 0;
}

int kdbus_msg_send_timeout(struct kdbus_conn *conn,
			   struct kdbus_msg *msg)
{
	struct kdbus_kmsg *kmsg;
	struct kdbus_msg_data *data;
	int ret;

	ret = kdbus_kmsg_new(conn, 0, &kmsg);
	if (ret < 0)
		return ret;

	kmsg->msg.dst_id = msg->src_id;
	kmsg->msg.src_id = KDBUS_SRC_ID_KERNEL;
	kmsg->msg.cookie_reply = msg->cookie;

	data = kmsg->msg.data;
	data->type = KDBUS_MSG_REPLY_TIMEOUT;

	ret = kdbus_kmsg_send(conn->ep, kmsg);
	kdbus_kmsg_unref(kmsg);

	return ret;
}

int kdbus_kmsg_send(struct kdbus_ep *ep, struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst = NULL;
	struct kdbus_msg *msg;
	u64 now_ns = 0;
	int ret = 0;

	/* augment incoming message */
	kmsg = kdbus_kmsg_append_timestamp(kmsg, &now_ns);

	msg = &kmsg->msg;
//	kdbus_msg_dump(msg);

	if (msg->dst_id == KDBUS_DST_ID_WELL_KNOWN_NAME) {
		const struct kdbus_msg_data *name_data;
		const struct kdbus_name_entry *name_entry;

		name_data = kdbus_msg_get_data(msg, KDBUS_MSG_DST_NAME, 0);
		if (!name_data) {
			pr_err("message %llu does not contain KDBUS_MSG_DST_NAME\n",
				(unsigned long long) msg->cookie);
			return -EINVAL;
		}

		/* lookup and determine conn_dst ... */
		name_entry = kdbus_name_lookup(ep->bus->name_registry,
					       name_data->data, 0);
		if (name_entry)
			conn_dst = name_entry->conn;

		if (!conn_dst)
			return -ENOENT;

		if ((msg->flags & KDBUS_MSG_FLAGS_NO_AUTO_START) && conn_dst->starter)
			return -ENOENT;

	} else if (msg->dst_id != KDBUS_DST_ID_BROADCAST) {
		/* direct message */
		conn_dst = idr_find(&ep->bus->conn_idr, msg->dst_id);
		if (!conn_dst)
			return -ENOENT;
	}

	if (conn_dst) {
		/* direct message */
		if (msg->timeout)
			kmsg->deadline = now_ns + msg->timeout;

		ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);

		if (msg->timeout)
			kdbus_conn_scan_timeout(conn_dst);
	} else {
		/* broadcast */
		struct kdbus_conn *tmp;

		list_for_each_entry_safe(conn_dst, tmp,
					 &ep->connection_list,
					 connection_entry) {
			if (conn_dst->type != KDBUS_CONN_EP)
				continue;

			if (conn_dst->id == msg->src_id)
				continue;

			ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);
			if (ret < 0)
				break;
		}
	}

	return ret;
}

int kdbus_kmsg_recv(struct kdbus_conn *conn, void __user *buf)
{
	u64 __user *msgsize = buf + offsetof(struct kdbus_msg, size);
	struct kdbus_msg_list_entry *entry;
	struct kdbus_msg *msg;
	u64 size;
	int ret;

	if (get_user(size, msgsize))
		return -EFAULT;

	mutex_lock(&conn->msg_lock);
	entry = list_first_entry(&conn->msg_list, struct kdbus_msg_list_entry, list);
	if (!entry) {
		ret = -ENOENT;
		goto out_unlock;
	}

	msg = &entry->kmsg->msg;
	if (size < msg->size) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	ret = copy_to_user(buf, msg, msg->size);
	if (ret == 0) {
		kdbus_kmsg_unref(entry->kmsg);
		list_del(&entry->list);
		kfree(entry);
	}

out_unlock:
	mutex_unlock(&conn->msg_lock);

	return ret;
}
