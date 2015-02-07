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

#ifndef __KDBUS_REPLY_H
#define __KDBUS_REPLY_H

/**
 * struct kdbus_reply - an entry of kdbus_conn's list of replies
 * @kref:		Ref-count of this object
 * @entry:		The entry of the connection's reply_list
 * @reply_src:		The connection the reply will be sent from
 * @reply_dst:		The connection the reply will be sent to
 * @queue_entry:	The queue entry item that is prepared by the replying
 *			connection
 * @deadline_ns:	The deadline of the reply, in nanoseconds
 * @cookie:		The cookie of the requesting message
 * @name_id:		ID of the well-known name the original msg was sent to
 * @sync:		The reply block is waiting for synchronous I/O
 * @waiting:		The condition to synchronously wait for
 * @interrupted:	The sync reply was left in an interrupted state
 * @err:		The error code for the synchronous reply
 */
struct kdbus_reply {
	struct kref kref;
	struct list_head entry;
	struct kdbus_conn *reply_src;
	struct kdbus_conn *reply_dst;
	struct kdbus_queue_entry *queue_entry;
	u64 deadline_ns;
	u64 cookie;
	u64 name_id;
	bool sync:1;
	bool waiting:1;
	bool interrupted:1;
	int err;
};

struct kdbus_reply *kdbus_reply_new(struct kdbus_conn *reply_src,
				    struct kdbus_conn *reply_dst,
				    const struct kdbus_msg *msg,
				    struct kdbus_name_entry *name_entry,
				    bool sync);

struct kdbus_reply *kdbus_reply_ref(struct kdbus_reply *r);
struct kdbus_reply *kdbus_reply_unref(struct kdbus_reply *r);

void kdbus_reply_link(struct kdbus_reply *r);
void kdbus_reply_unlink(struct kdbus_reply *r);

struct kdbus_reply *kdbus_reply_find(struct kdbus_conn *replying,
				     struct kdbus_conn *reply_dst,
				     u64 cookie);

void kdbus_sync_reply_wakeup(struct kdbus_reply *reply, int err);
void kdbus_reply_list_scan_work(struct work_struct *work);

#endif /* __KDBUS_REPLY_H */
