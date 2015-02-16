#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uio.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "message.h"
#include "metadata.h"
#include "names.h"
#include "domain.h"
#include "item.h"
#include "notify.h"
#include "policy.h"
#include "reply.h"
#include "util.h"

/**
 * kdbus_reply_new() - Allocate and set up a new kdbus_reply object
 * @reply_src:		The connection a reply is expected from
 * @reply_dst:		The connection this reply object belongs to
 * @msg:		Message associated with the reply
 * @name_entry:		Name entry used to send the message
 * @sync:		Whether or not to make this reply synchronous
 *
 * Allocate and fill a new kdbus_reply object.
 *
 * Return: New kdbus_conn object on success, ERR_PTR on error.
 */
struct kdbus_reply *kdbus_reply_new(struct kdbus_conn *reply_src,
				    struct kdbus_conn *reply_dst,
				    const struct kdbus_msg *msg,
				    struct kdbus_name_entry *name_entry,
				    bool sync)
{
	struct kdbus_reply *r;
	int ret = 0;

	if (atomic_inc_return(&reply_dst->request_count) >
	    KDBUS_CONN_MAX_REQUESTS_PENDING) {
		ret = -EMLINK;
		goto exit_dec_request_count;
	}

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r) {
		ret = -ENOMEM;
		goto exit_dec_request_count;
	}

	kref_init(&r->kref);
	INIT_LIST_HEAD(&r->entry);
	r->reply_src = kdbus_conn_ref(reply_src);
	r->reply_dst = kdbus_conn_ref(reply_dst);
	r->cookie = msg->cookie;
	r->name_id = name_entry ? name_entry->name_id : 0;
	r->deadline_ns = msg->timeout_ns;

	if (sync) {
		r->sync = true;
		r->waiting = true;
	}

exit_dec_request_count:
	if (ret < 0) {
		atomic_dec(&reply_dst->request_count);
		return ERR_PTR(ret);
	}

	return r;
}

static void __kdbus_reply_free(struct kref *kref)
{
	struct kdbus_reply *reply =
		container_of(kref, struct kdbus_reply, kref);

	atomic_dec(&reply->reply_dst->request_count);
	kdbus_conn_unref(reply->reply_src);
	kdbus_conn_unref(reply->reply_dst);
	kfree(reply);
}

/**
 * kdbus_reply_ref() - Increase reference on kdbus_reply
 * @r:		The reply, may be %NULL
 *
 * Return: The reply object with an extra reference
 */
struct kdbus_reply *kdbus_reply_ref(struct kdbus_reply *r)
{
	if (r)
		kref_get(&r->kref);
	return r;
}

/**
 * kdbus_reply_unref() - Decrease reference on kdbus_reply
 * @r:		The reply, may be %NULL
 *
 * Return: NULL
 */
struct kdbus_reply *kdbus_reply_unref(struct kdbus_reply *r)
{
	if (r)
		kref_put(&r->kref, __kdbus_reply_free);
	return NULL;
}

/**
 * kdbus_reply_link() - Link reply object into target connection
 * @r:		Reply to link
 */
void kdbus_reply_link(struct kdbus_reply *r)
{
	if (WARN_ON(!list_empty(&r->entry)))
		return;

	list_add(&r->entry, &r->reply_dst->reply_list);
	kdbus_reply_ref(r);
}

/**
 * kdbus_reply_unlink() - Unlink reply object from target connection
 * @r:		Reply to unlink
 */
void kdbus_reply_unlink(struct kdbus_reply *r)
{
	if (!list_empty(&r->entry)) {
		list_del_init(&r->entry);
		kdbus_reply_unref(r);
	}
}

/**
 * kdbus_sync_reply_wakeup() - Wake a synchronously blocking reply
 * @reply:	The reply object
 * @err:	Error code to set on the remote side
 *
 * Remove the synchronous reply object from its connection reply_list, and
 * wake up remote peer (method origin) with the appropriate synchronous reply
 * code.
 */
void kdbus_sync_reply_wakeup(struct kdbus_reply *reply, int err)
{
	if (WARN_ON(!reply->sync))
		return;

	reply->waiting = false;
	reply->err = err;
	wake_up_interruptible(&reply->reply_dst->wait);
}

/**
 * kdbus_reply_find() - Find the corresponding reply object
 * @replying:	The replying connection or NULL
 * @reply_dst:	The connection the reply will be sent to
 *		(method origin)
 * @cookie:	The cookie of the requesting message
 *
 * Lookup a reply object that should be sent as a reply by
 * @replying to @reply_dst with the given cookie.
 *
 * Callers must take the @reply_dst lock.
 *
 * Return: the corresponding reply object or NULL if not found
 */
struct kdbus_reply *kdbus_reply_find(struct kdbus_conn *replying,
				     struct kdbus_conn *reply_dst,
				     u64 cookie)
{
	struct kdbus_reply *r, *reply = NULL;

	list_for_each_entry(r, &reply_dst->reply_list, entry) {
		if (r->cookie == cookie &&
		    (!replying || r->reply_src == replying)) {
			reply = r;
			break;
		}
	}

	return reply;
}

/**
 * kdbus_reply_list_scan_work() - Worker callback to scan the replies of a
 *				  connection for exceeded timeouts
 * @work:		Work struct of the connection to scan
 *
 * Walk the list of replies stored with a connection and look for entries
 * that have exceeded their timeout. If such an entry is found, a timeout
 * notification is sent to the waiting peer, and the reply is removed from
 * the list.
 *
 * The work is rescheduled to the nearest timeout found during the list
 * iteration.
 */
void kdbus_reply_list_scan_work(struct work_struct *work)
{
	struct kdbus_conn *conn =
		container_of(work, struct kdbus_conn, work.work);
	struct kdbus_reply *reply, *reply_tmp;
	u64 deadline = ~0ULL;
	struct timespec64 ts;
	u64 now;

	ktime_get_ts64(&ts);
	now = timespec64_to_ns(&ts);

	mutex_lock(&conn->lock);
	if (!kdbus_conn_active(conn)) {
		mutex_unlock(&conn->lock);
		return;
	}

	list_for_each_entry_safe(reply, reply_tmp, &conn->reply_list, entry) {
		/*
		 * If the reply block is waiting for synchronous I/O,
		 * the timeout is handled by wait_event_*_timeout(),
		 * so we don't have to care for it here.
		 */
		if (reply->sync && !reply->interrupted)
			continue;

		WARN_ON(reply->reply_dst != conn);

		if (reply->deadline_ns > now) {
			/* remember next timeout */
			if (deadline > reply->deadline_ns)
				deadline = reply->deadline_ns;

			continue;
		}

		/*
		 * A zero deadline means the connection died, was
		 * cleaned up already and the notification was sent.
		 * Don't send notifications for reply trackers that were
		 * left in an interrupted syscall state.
		 */
		if (reply->deadline_ns != 0 && !reply->interrupted)
			kdbus_notify_reply_timeout(conn->ep->bus, conn->id,
						   reply->cookie);

		kdbus_reply_unlink(reply);
	}

	/* rearm delayed work with next timeout */
	if (deadline != ~0ULL)
		schedule_delayed_work(&conn->work,
				      nsecs_to_jiffies(deadline - now));

	mutex_unlock(&conn->lock);

	kdbus_notify_flush(conn->ep->bus);
}
