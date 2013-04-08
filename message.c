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

#define KDBUS_MSG_HEADER_SIZE offsetof(struct kdbus_msg, data)
#define KDBUS_KMSG_HEADER_SIZE offsetof(struct kdbus_kmsg, msg)
#define KDBUS_MSG_DATA_HEADER_SIZE offsetof(struct kdbus_msg_data, data)
#define KDBUS_MSG_DATA_ALIGN(s) ALIGN((s), sizeof(u64))
#define KDBUS_MSG_DATA_SIZE(s) \
	ALIGN((s) + KDBUS_MSG_DATA_HEADER_SIZE, sizeof(u64))
#define KDBUS_MSG_DATA_NEXT(_data) \
	(struct kdbus_msg_data *)(((u8 *)_data) + (_data->size))
#define KDBUS_MSG_DATA_FOREACH(_msg, _data, _size) \
	for (_data = (_msg)->data, _size = (_msg)->size - KDBUS_MSG_HEADER_SIZE; \
	     _size > 0 && _size >= (_data)->size; \
	     _size -= (_data)->size, _data = KDBUS_MSG_DATA_NEXT(_data))

static void kdbus_msg_dump(const struct kdbus_msg *msg);

static void kdbus_kmsg_free(struct kdbus_kmsg *kmsg)
{
	if (kmsg->fds) {
		int i;

		for (i = 0; i < kmsg->fds->count; i++)
			; //FIXME:
		kfree(kmsg->fds);
	}

	if (kmsg->payloads) {
		int i;

		for (i = 0; i < kmsg->payloads->count; i++)
			kfree(kmsg->payloads->data[i]);

		kfree(kmsg->payloads);
	}

	kfree(kmsg->meta);
	kfree(kmsg);
}

static void __kdbus_kmsg_free(struct kref *kref)
{
	struct kdbus_kmsg *kmsg = container_of(kref, struct kdbus_kmsg, kref);

	return kdbus_kmsg_free(kmsg);
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

int kdbus_kmsg_new(u64 extra_size, struct kdbus_kmsg **m)
{
	u64 size = sizeof(struct kdbus_kmsg) + KDBUS_MSG_DATA_SIZE(extra_size);
	struct kdbus_kmsg *kmsg;

	kmsg = kzalloc(size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;

	kref_init(&kmsg->kref);

	kmsg->msg.size = size - KDBUS_KMSG_HEADER_SIZE;
	kmsg->msg.data[0].size = KDBUS_MSG_DATA_SIZE(extra_size);

	*m = kmsg;
	return 0;
}

static int kdbus_msg_scan_data(struct kdbus_kmsg *kmsg)
{
	const struct kdbus_msg *msg = &kmsg->msg;
	const struct kdbus_msg_data *data;
	u64 size;
	int num_fds = 0;
	int num_payloads = 0;
	bool name = false;
	bool bloom = false;
	int ret;

	KDBUS_MSG_DATA_FOREACH(msg, data, size) {
		/* Ensure we actually have some data */
		if (data->size <= KDBUS_MSG_DATA_SIZE(0))
			return -EINVAL;

		switch (data->type) {
		case KDBUS_MSG_PAYLOAD:
			if (data->size > 0xffff)
				return -EMSGSIZE;
			break;

		case KDBUS_MSG_PAYLOAD_REF:
			if (data->size != KDBUS_MSG_DATA_HEADER_SIZE + 16)
				return -EINVAL;
			if (data->data_ref.size > 0xffff)
				return -EMSGSIZE;
			num_payloads++;
			break;

		case KDBUS_MSG_UNIX_FDS:
			/* do not allow to broadcast file descriptors */
			if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
				return -EINVAL;
			num_fds += data->size / sizeof(int);
			break;

		case KDBUS_MSG_BLOOM:
			/* bloom filters are for broadcast messages */
			if (msg->dst_id != KDBUS_DST_ID_BROADCAST)
				return -EINVAL;

			/* do not allow multiple bloom filters */
			if (bloom)
				return -EINVAL;
			bloom = true;
			break;

		case KDBUS_MSG_DST_NAME:
			/* do not allow multiple names */
			if (name)
				return -EINVAL;
			name = true;
			break;

		default:
			return -ENOTSUPP;
		}
	}

	/* bloom filters are for undirected messages only */
	if (name && bloom)
		return -EINVAL;

	/* allocate array for file descriptors */
	if (num_fds > 256)
		return -EINVAL;

	if (num_fds > 0) {
		struct kdbus_fds *fds;

		fds = kzalloc(sizeof(struct kdbus_fds) +
			      (num_fds * sizeof(struct file *)), GFP_KERNEL);
		if (!fds) {
			ret = -ENOMEM;
			goto out_err;
		}

		kmsg->fds = fds;
	}

	/* allocate array for payload references */
	if (num_payloads > 256)
		return -EINVAL;

	if (num_payloads > 0) {
		struct kdbus_payload *pls;

		pls = kzalloc(sizeof(struct kdbus_payload) + (num_payloads *
				sizeof(struct kdbus_msg_data *)), GFP_KERNEL);
		if (!pls) {
			ret = -ENOMEM;
			goto out_err;
		}

		kmsg->payloads = pls;
	}

	return 0;

out_err:
	kfree(kmsg->fds);
	kfree(kmsg->payloads);

	return ret;
}

/*
 * Copy one data reference into our kmsg payload array; the
 * KDBUS_MSG_PAYLOAD_REF record is hereby converted into a
 * KDBUS_MSG_PAYLOAD record
 */
static int kdbus_copy_user_payload(struct kdbus_kmsg *kmsg,
				   const struct kdbus_msg_data *data)
{
	u64 size;
	struct kdbus_msg_data *d;
	void __user *user_addr;

	size = KDBUS_MSG_DATA_HEADER_SIZE + data->data_ref.size;

	d = kmalloc(size, GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	d->size = size;
	d->type = KDBUS_MSG_PAYLOAD;

	user_addr = (void __user *)data->data_ref.address;
	if (copy_from_user(&d->data, user_addr, data->data_ref.size)) {
		kfree(d);
		return -ENOMEM;
	}

	kmsg->payloads->data[kmsg->payloads->count++] = d;

	return 0;
}

/*
 * Copy passed file descriptors into "kmsg".
 * - allocate a chunk of file * and map the "handles" to pointers,
 * - grabbing references to them so that they can't go away
 */
static int kdbus_copy_user_fds(struct kdbus_kmsg *kmsg,
			       const struct kdbus_msg_data *data)
{
	return 0;
}

/*
 * Check the validity of a message. The general layout of the received message
 * is not altered before it is delivered, a couple of data fields need to be
 * filled-in and updated though.
 * Kernel-internal data is stored in the enclosing "kmsg" structure, which
 * contains the received userspace "msg".
 */
int kdbus_kmsg_new_from_user(struct kdbus_conn *conn, void __user *buf,
			     struct kdbus_kmsg **m)
{
	struct kdbus_kmsg *kmsg;
	const struct kdbus_msg_data *data;
	u64 size, alloc_size;
	int ret;

	if (kdbus_size_get_user(size, buf, struct kdbus_msg))
		return -EFAULT;

	if (size < sizeof(struct kdbus_msg) || size > 0xffff)
		return -EMSGSIZE;

	alloc_size = size + KDBUS_KMSG_HEADER_SIZE;

	kmsg = kmalloc(alloc_size, GFP_KERNEL);
	if (!kmsg)
		return -ENOMEM;

	memset(kmsg, 0, KDBUS_KMSG_HEADER_SIZE);

	if (copy_from_user(&kmsg->msg, buf, size)) {
		ret = -EFAULT;
		goto out_err;
	}

	/* check validity and prepare handling of reference data records */
	ret = kdbus_msg_scan_data(kmsg);
	if (ret < 0)
		goto out_err;

	/* fill in sender ID */
	kmsg->msg.src_id = conn->id;

	/*
	 * iterate over the receiced data records and resolve external
	 * references and store them in "struct kmsg"
	 */
	KDBUS_MSG_DATA_FOREACH(&kmsg->msg, data, size) {
		switch (data->type) {
		case KDBUS_MSG_PAYLOAD_REF:
			ret = kdbus_copy_user_payload(kmsg, data);
			if (ret < 0)
				goto out_err;
			break;

		case KDBUS_MSG_UNIX_FDS:
			ret = kdbus_copy_user_fds(kmsg, data);
			if (ret < 0)
				goto out_err;
			break;
		}
	}

	kref_init(&kmsg->kref);

	*m = kmsg;
	return 0;

out_err:
	kdbus_kmsg_free(kmsg);
	return ret;
}

static const struct kdbus_msg_data *
kdbus_msg_get_data(const struct kdbus_msg *msg, u64 type, int index)
{
	const struct kdbus_msg_data *data;
	u64 size;

	KDBUS_MSG_DATA_FOREACH(msg, data, size) {
		if (data->type == type && index-- == 0)
			return data;
	}

	return NULL;
}

static void __maybe_unused kdbus_msg_dump(const struct kdbus_msg *msg)
{
	const struct kdbus_msg_data *data;
	u64 size;

	pr_info("msg size=%llu, flags=0x%llx, dst_id=%llu, src_id=%llu, "
		"cookie=0x%llx payload_type=0x%llx, timeout=%llu\n",
		(unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		(unsigned long long) msg->dst_id,
		(unsigned long long) msg->src_id,
		(unsigned long long) msg->cookie,
		(unsigned long long) msg->payload_type,
		(unsigned long long) msg->timeout_ns);

	KDBUS_MSG_DATA_FOREACH(msg, data, size) {
		pr_info("`- msg_data size=%llu, type=0x%llx\n",
			data->size, data->type);
	}
}

static struct kdbus_msg_data __must_check *
kdbus_kmsg_append_metadata(struct kdbus_kmsg *kmsg, u64 extra_size)
{
	struct kdbus_msg_data *data;
	u64 size;

	/* get new metadata buffer, pre-allocate at least 256 bytes */
	if (!kmsg->meta) {
		size = roundup_pow_of_two(128 + KDBUS_MSG_DATA_ALIGN(extra_size));
		kmsg->meta = kzalloc(size, GFP_KERNEL);
		if (!kmsg->meta)
			return NULL;

		kmsg->meta->size = offsetof(struct kdbus_meta, data);
		kmsg->meta->allocated_size = size;
	}

	/* double the pre-allocated buffer size if needed */
	size = kmsg->meta->size + KDBUS_MSG_DATA_ALIGN(extra_size);
	if (size > kmsg->meta->allocated_size) {
		struct kdbus_meta *meta;

		pr_info("kdbus_kmsg_append_metadata: grow to size=%llu\n", size);

		size = roundup_pow_of_two(size);
		meta = kmalloc(size, GFP_KERNEL);
		if (!meta)
			return NULL;

		memcpy(meta, kmsg->meta, kmsg->meta->allocated_size);
		memset(meta + kmsg->meta->allocated_size, 0,
		       size - kmsg->meta->allocated_size);
		meta->allocated_size = size;

		kfree(kmsg->meta);
		kmsg->meta = meta;
	}

	/* insert new record */
	data = (struct kdbus_msg_data *)((u8 *)kmsg->meta + kmsg->meta->size);
	kmsg->meta->size += KDBUS_MSG_DATA_ALIGN(extra_size);

	return data;
}

static int __must_check
kdbus_kmsg_append_timestamp(struct kdbus_kmsg *kmsg, u64 *now_ns)
{
	struct kdbus_msg_data *data;
	u64 size = KDBUS_MSG_DATA_SIZE(sizeof(u64));
	struct timespec ts;

	data = kdbus_kmsg_append_metadata(kmsg, size);
	if (!data)
		return -ENOMEM;

	ktime_get_ts(&ts);
	data->type = KDBUS_MSG_TIMESTAMP;
	data->size = size;
	data->ts_ns = (ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;

	if (now_ns)
		*now_ns = data->ts_ns;

	return 0;
}

static int __must_check
kdbus_kmsg_append_src_names(struct kdbus_kmsg *kmsg,
			    struct kdbus_conn *conn)
{
	struct kdbus_name_entry *name_entry;
	struct kdbus_msg_data *data;
	u64 pos = 0, size, strsize = 0;

	mutex_lock(&conn->names_lock);
	list_for_each_entry(name_entry, &conn->names_list, conn_entry)
		strsize += strlen(name_entry->name) + 1;

	/* no names? then don't do anything */
	if (strsize == 0)
		goto exit_unlock;

	size = strsize + KDBUS_MSG_DATA_SIZE(0);
	data = kdbus_kmsg_append_metadata(kmsg, size);
	if (!data)
		return -ENOMEM;

	data->type = KDBUS_MSG_SRC_NAMES;
	data->size = size;

	list_for_each_entry(name_entry, &conn->names_list, conn_entry) {
		strcpy(data->data + pos, name_entry->name);
		pos += strlen(name_entry->name) + 1;
	}

exit_unlock:
	mutex_unlock(&conn->names_lock);

	return 0;
}

static int __must_check
kdbus_kmsg_append_cred(struct kdbus_kmsg *kmsg,
		       const struct kdbus_creds *creds)
{
	struct kdbus_msg_data *data;
	u64 size = KDBUS_MSG_DATA_SIZE(sizeof(struct kdbus_creds));

	data = kdbus_kmsg_append_metadata(kmsg, size);
	if (!data)
		return -ENOMEM;

	data->type = KDBUS_MSG_SRC_CREDS;
	data->size = size;
	memcpy(&data->creds, creds, sizeof(*creds));

	return 0;
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

int kdbus_kmsg_send(struct kdbus_ep *ep,
		    struct kdbus_conn *conn_src,
		    struct kdbus_kmsg *kmsg)
{
	struct kdbus_conn *conn_dst = NULL;
	const struct kdbus_msg *msg;
	u64 now_ns = 0;
	int ret;

	/* augment incoming message */
	ret = kdbus_kmsg_append_timestamp(kmsg, &now_ns);
	if (ret < 0)
		return ret;

	if (conn_src) {
		ret = kdbus_kmsg_append_src_names(kmsg, conn_src);
		if (ret < 0)
			return ret;

		ret = kdbus_kmsg_append_cred(kmsg, &conn_src->creds);
		if (ret < 0)
			return ret;
	}

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
		conn_dst = kdbus_bus_find_conn_by_id(ep->bus, msg->dst_id);
		if (!conn_dst)
			return -ENOENT;
	}

	if (conn_dst) {
		/* check policy */
		if (ep->policy_db && conn_src) {
			ret = kdbus_policy_db_check_send_access(ep->policy_db,
								conn_src,
								conn_dst);
			if (ret < 0)
				return ret;
		}

		/* direct message */
		if (msg->timeout_ns)
			kmsg->deadline_ns = now_ns + msg->timeout_ns;

		ret = kdbus_conn_enqueue_kmsg(conn_dst, kmsg);

		if (msg->timeout_ns)
			kdbus_conn_schedule_timeout_scan(conn_dst);
	} else {
		/* broadcast */
		/* timeouts are not allowed for broadcasts */
		if (msg->timeout_ns)
			return -EINVAL;

		list_for_each_entry(conn_dst, &ep->connection_list,
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
	struct kdbus_msg_list_entry *entry;
	const struct kdbus_kmsg *kmsg;
	const struct kdbus_msg *msg;
	const struct kdbus_msg_data *data;
	u64 size, pos, final_size;
	int payload_ref = 0;
	int ret;

	if (kdbus_size_get_user(size, buf, struct kdbus_msg))
		return -EFAULT;

	mutex_lock(&conn->msg_lock);
	entry = list_first_entry(&conn->msg_list, struct kdbus_msg_list_entry, list);
	if (!entry) {
		ret = -ENOENT;
		goto out_unlock;
	}

	kmsg = entry->kmsg;
	msg = &kmsg->msg;

	final_size = msg->size;
	if (kmsg->meta)
		final_size += kmsg->meta->size - offsetof(struct kdbus_meta, data);

	if (kmsg->payloads) {
		int i;

		for (i = 0; i < kmsg->payloads->count; i++)
			final_size += KDBUS_MSG_DATA_ALIGN(kmsg->payloads->data[i]->size);
	}

	if (size < final_size ) {
		ret = -ENOBUFS;
		goto out_unlock;
	}

	/* copy the message header */
	ret = copy_to_user(buf, msg, KDBUS_MSG_HEADER_SIZE);
	if (ret)
		goto out_unlock;

	/* append the data records */
	pos = KDBUS_MSG_HEADER_SIZE;

	KDBUS_MSG_DATA_FOREACH(msg, data, size) {
		switch (data->type) {
		case KDBUS_MSG_PAYLOAD_REF: {
			struct kdbus_msg_data *d;

			/* insert data passed-in by reference */
			d = kmsg->payloads->data[payload_ref++];
			ret = copy_to_user(buf + pos, d, d->size);
			if (ret)
				goto out_unlock;

			payload_ref++;
			pos += KDBUS_MSG_DATA_ALIGN(d->size);
			break;
		}

		case KDBUS_MSG_UNIX_FDS:
			/* install passed-in file descritors into client process */
			break;

		default:
			ret = copy_to_user(buf + pos, data, data->size);
			if (ret)
				goto out_unlock;
			pos += KDBUS_MSG_DATA_ALIGN(data->size);
		}
	}

	/* append metadata records */
	if (kmsg->meta) {
		ret = copy_to_user(buf + pos, kmsg->meta->data,
				   kmsg->meta->size - offsetof(struct kdbus_meta, data));
		if (ret)
			goto out_unlock;
	}

	/* update the final returned data size in the message header */
	ret = kdbus_size_set_user(final_size, buf, struct kdbus_msg);
	if (ret)
		goto out_unlock;

	list_del(&entry->list);
	kdbus_kmsg_unref(entry->kmsg);
	kfree(entry);

out_unlock:
	mutex_unlock(&conn->msg_lock);

	return ret;
}
