/*
 * kdbus - interprocess message routing
 *
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
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
//#include <uapi/linux/major.h>
#include "kdbus.h"

#include "kdbus_internal.h"

static void __kdbus_kmsg_free(struct kref *kref)
{
	struct kdbus_kmsg *kmsg = container_of(kref, struct kdbus_kmsg, kref);
	kfree(kmsg);
}

static void kdbus_kmsg_unref(struct kdbus_kmsg *kmsg)
{
	kref_put(&kmsg->kref, __kdbus_kmsg_free);
}

static struct kdbus_kmsg *kdbus_kmsg_ref(struct kdbus_kmsg *kmsg)
{
	kref_get(&kmsg->kref);
	return kmsg;
}

int kdbus_kmsg_new(struct kdbus_conn *conn, void __user *argp,
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

/*
	if (m->src_id == 0) {
		err = -EINVAL;
		goto out_err;
	}
*/
	kmsg->msg.src_id = conn->id;
	kref_init(&kmsg->kref);

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

static void kdbus_msg_dump(const struct kdbus_msg *msg)
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
kdbus_kmsg_append_timestamp(struct kdbus_kmsg *kmsg)
{
	struct kdbus_msg_data *data;
	u64 size = sizeof(*kmsg) + sizeof(u64);
	struct timespec ts;

	data = kzalloc(size, GFP_KERNEL);
	if (!data)
		return NULL;

	ktime_get_ts(&ts);

	data->size = size;
	data->type = KDBUS_MSG_TIMESTAMP;
	data->data_u64[0] = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
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
	list_add_tail(&conn->msg_list, &entry->list);
	mutex_unlock(&conn->msg_lock);

	wake_up_interruptible(&conn->ep->wait);

	return 0;
}

static struct kdbus_kmsg *kdbus_conn_dequeue_kmsg(struct kdbus_conn *conn)
{
	struct kdbus_msg_list_entry *entry;
	struct kdbus_kmsg *kmsg = NULL;

	mutex_lock(&conn->msg_lock);
	entry = list_first_entry(&conn->msg_list, struct kdbus_msg_list_entry, list);
	if (entry) {
		kmsg = entry->kmsg;
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&conn->msg_lock);

	return kmsg;
}

int kdbus_kmsg_send(struct kdbus_conn *conn, struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst = NULL;
	struct kdbus_msg *msg;
	int ret = 0;

	/* augment incoming message */
	kmsg = kdbus_kmsg_append_timestamp(kmsg);

	msg = &kmsg->msg;
//	kdbus_msg_dump(msg);

	if (msg->dst_id == 0) {
		/* look up well-known name from supplied data */
		const struct kdbus_msg_data *name_data;

		name_data = kdbus_msg_get_data(msg, KDBUS_MSG_DST_NAMES, 0);
		if (!name_data) {
			pr_err("message %llu does not contain KDBUS_MSG_DST_NAMES\n",
				(unsigned long long) msg->cookie);
			return -EINVAL;
		}

		pr_info("name in message: >%s<\n", name_data->data);
		/* lookup and determine conn_dst ... */
		/* ... */
		if (!conn_dst)
			return -ENOENT;
	} else if (msg->dst_id != ~0ULL) {
		/* direct message */
		conn_dst = idr_find(&conn->ep->bus->conn_idr, msg->dst_id);
		if (!conn_dst)
			return -ENOENT;
	}

	if (conn_dst) {
		/* direct message */
		ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);
	} else {
		/* broadcast */
		struct kdbus_conn *tmp;

		list_for_each_entry_safe(conn_dst, tmp,
					 &conn->ep->connection_list,
					 connection_entry) {
			if (conn_dst->type != KDBUS_CONN_EP)
				continue;

			ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);
			if (ret < 0)
				break;
		}
	}

	kdbus_kmsg_unref(kmsg);

	return ret;
}

int kdbus_kmsg_recv(struct kdbus_conn *conn, void __user *buf)
{
	struct kdbus_kmsg *kmsg = kdbus_conn_dequeue_kmsg(conn);
	int ret;

	if (!kmsg)
		return -ENOENT;

	ret = copy_to_user(buf, &kmsg->msg, kmsg->msg.size);
	kdbus_kmsg_unref(kmsg);

	return ret;
}

