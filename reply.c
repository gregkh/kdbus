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
#include "domain.h"
#include "item.h"
#include "notify.h"
#include "policy.h"
#include "reply.h"
#include "util.h"

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

struct kdbus_reply *kdbus_reply_ref(struct kdbus_reply *r)
{
	if (r)
		kref_get(&r->kref);
	return r;
}

struct kdbus_reply *kdbus_reply_unref(struct kdbus_reply *r)
{
	if (r)
		kref_put(&r->kref, __kdbus_reply_free);
	return NULL;
}

/*
 * Remove the synchronous reply object from its connection
 * reply_list, and wakeup remote peer (method origin) with the
 * appropriate synchronous reply code
 */
void kdbus_sync_reply_wakeup(struct kdbus_reply *reply, int err)
{
	if (WARN_ON(!reply->sync))
		return;

	list_del_init(&reply->entry);
	reply->waiting = false;
	reply->err = err;
	wake_up_interruptible(&reply->reply_dst->wait);
}

/**
 * kdbus_reply_find() - Find the corresponding reply object
 * @replying:	The replying connection
 * @reply_dst:	The connection the reply will be sent to
 *		(method origin)
 * @cookie:	The cookie of the requesting message
 *
 * Lookup a reply object that should be sent as a reply by
 * @replying to @reply_dst with the given cookie.
 *
 * For optimizations, callers should first check 'request_count' of
 * @reply_dst to see if the connection has issued any requests
 * that are waiting for replies, before calling this function.
 *
 * Callers must take the @reply_dst lock.
 *
 * Return: the corresponding reply object or NULL if not found
 */
struct kdbus_reply * kdbus_reply_find(struct kdbus_conn *replying,
				      struct kdbus_conn *reply_dst,
				      u64 cookie)
{
	struct kdbus_reply *r, *reply = NULL;

	list_for_each_entry(r, &reply_dst->reply_list, entry) {
		if (r->reply_src == replying &&
		    r->cookie == cookie) {
			reply = r;
			break;
		}
	}

	return reply;
}

void kdbus_reply_list_scan(struct kdbus_conn *conn)
{
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

		list_del_init(&reply->entry);
		kdbus_reply_unref(reply);
	}

	/* rearm delayed work with next timeout */
	if (deadline != ~0ULL)
		schedule_delayed_work(&conn->work,
				      nsecs_to_jiffies(deadline - now));

	mutex_unlock(&conn->lock);

	kdbus_notify_flush(conn->ep->bus);
}
