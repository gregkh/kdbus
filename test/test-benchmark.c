#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <locale.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#define SERVICE_NAME "foo.bar.echo"

static const bool use_memfd = true;		/* transmit memfd? */
static const bool compare_uds = false;		/* unix-socket comparison? */
static const bool attach_none = false;		/* clear attach-flags? */
static char stress_payload[8192];

struct stats {
	uint64_t count;
	uint64_t latency_acc;
	uint64_t latency_low;
	uint64_t latency_high;
};

static struct stats stats;

static uint64_t now(void)
{
	struct timespec spec;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spec);
	return spec.tv_sec * 1000ULL * 1000ULL * 1000ULL + spec.tv_nsec;
}

static void reset_stats(void)
{
	stats.count = 0;
	stats.latency_acc = 0;
	stats.latency_low = UINT64_MAX;
	stats.latency_high = 0;
}

static void dump_stats(bool is_uds)
{
	if (stats.count > 0) {
		kdbus_printf("stats %s: %'llu packets processed, latency (nsecs) min/max/avg %'7llu // %'7llu // %'7llu\n",
			     is_uds ? " (UNIX)" : "(KDBUS)",
			     (unsigned long long) stats.count,
			     (unsigned long long) stats.latency_low,
			     (unsigned long long) stats.latency_high,
			     (unsigned long long) (stats.latency_acc / stats.count));
	} else {
		kdbus_printf("*** no packets received. bus stuck?\n");
	}
}

static void add_stats(uint64_t prev)
{
	uint64_t diff;

	diff = now() - prev;

	stats.count++;
	stats.latency_acc += diff;
	if (stats.latency_low > diff)
		stats.latency_low = diff;

	if (stats.latency_high < diff)
		stats.latency_high = diff;
}

static int
send_echo_request(struct kdbus_conn *conn, uint64_t dst_id)
{
	struct kdbus_msg *msg;
	struct kdbus_item *item;
	uint64_t size;
	int memfd = -1;
	int ret;
	uint64_t now_ns;

	now_ns = now();

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	if (use_memfd) {
		memfd = sys_memfd_create("memfd-name", 0);
		ASSERT_RETURN_VAL(memfd >= 0, memfd);

		ret = write(memfd, &now_ns, sizeof(now_ns));
		ASSERT_RETURN_VAL(ret == sizeof(now_ns), -EAGAIN);

		ret = sys_memfd_seal_set(memfd);
		ASSERT_RETURN_VAL(ret == 0, -errno);

		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
	}

	msg = malloc(size);
	ASSERT_RETURN_VAL(msg, -ENOMEM);

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = conn->id;
	msg->dst_id = dst_id;
	msg->payload_type = KDBUS_PAYLOAD_DBUS;

	item = msg->items;

	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t) stress_payload;
	item->vec.size = sizeof(stress_payload);
	item = KDBUS_ITEM_NEXT(item);

	if (use_memfd) {
		item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
		item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_memfd);
		item->memfd.size = sizeof(now_ns);
		item->memfd.fd = memfd;
		item = KDBUS_ITEM_NEXT(item);
	}

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	ASSERT_RETURN_VAL(ret == 0, -errno);

	close(memfd);
	free(msg);

	return 0;
}

static int
handle_echo_reply(struct kdbus_conn *conn, uint64_t send_ns)
{
	int ret;
	struct kdbus_cmd_recv recv = {};
	struct kdbus_msg *msg;
	const struct kdbus_item *item;
	bool has_memfd = false;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	if (ret < 0 && errno == EAGAIN)
		return -EAGAIN;

	ASSERT_RETURN_VAL(ret == 0, -errno);

	msg = (struct kdbus_msg *)(conn->buf + recv.offset);
	item = msg->items;

	KDBUS_ITEM_FOREACH(item, msg, items) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			char *buf;

			buf = mmap(NULL, item->memfd.size, PROT_READ,
				   MAP_PRIVATE, item->memfd.fd, 0);
			ASSERT_RETURN_VAL(buf != MAP_FAILED, -EINVAL);
			ASSERT_RETURN_VAL(item->memfd.size == sizeof(uint64_t),
					  -EINVAL);

			add_stats(*(uint64_t*)buf);
			munmap(buf, item->memfd.size);
			close(item->memfd.fd);
			has_memfd = true;
			break;
		}

		case KDBUS_ITEM_PAYLOAD_OFF: {
			/* ignore */
			break;
		}
		}
	}

	if (!has_memfd)
		add_stats(send_ns);

	ret = kdbus_free(conn, recv.offset);
	ASSERT_RETURN_VAL(ret == 0, -errno);

	return 0;
}

int kdbus_test_benchmark(struct kdbus_test_env *env)
{
	static char buf[sizeof(stress_payload)];
	int ret;
	struct kdbus_conn *conn_a, *conn_b;
	struct pollfd fds[2];
	uint64_t start, send_ns, now_ns, diff;
	unsigned int i;
	int uds[2];

	setlocale(LC_ALL, "");

	for (i = 0; i < sizeof(stress_payload); i++)
		stress_payload[i] = i;

	/* setup kdbus pair */

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	ret = kdbus_add_match_empty(conn_a);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(conn_b);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(conn_a, SERVICE_NAME, NULL);
	ASSERT_RETURN(ret == 0);

	if (attach_none) {
		ret = kdbus_conn_update_attach_flags(conn_a, 0);
		ASSERT_RETURN(ret == 0);
	}

	/* setup UDS pair */

	ret = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, uds);
	ASSERT_RETURN(ret == 0);

	/* start benchmark */

	kdbus_printf("-- entering poll loop ...\n");

	do {
		/* run kdbus benchmark */

		fds[0].fd = conn_a->fd;
		fds[1].fd = conn_b->fd;

		/* cancel any prending message */
		handle_echo_reply(conn_a, 0);

		start = now();
		reset_stats();

		send_ns = now();
		ret = send_echo_request(conn_b, conn_a->id);
		ASSERT_RETURN(ret == 0);

		while (1) {
			unsigned int nfds = sizeof(fds) / sizeof(fds[0]);
			unsigned int i;

			for (i = 0; i < nfds; i++) {
				fds[i].events = POLLIN | POLLPRI | POLLHUP;
				fds[i].revents = 0;
			}

			ret = poll(fds, nfds, 10);
			if (ret < 0)
				break;

			if (fds[0].revents & POLLIN) {
				ret = handle_echo_reply(conn_a, send_ns);
				if (ret)
					break;

				send_ns = now();
				ret = send_echo_request(conn_b, conn_a->id);
				if (ret)
					break;
			}

			now_ns = now();
			diff = now_ns - start;
			if (diff > 1000000000ULL) {
				start = now_ns;

				dump_stats(false);
				reset_stats();

				break;
			}
		}

		if (!compare_uds)
			continue;

		/* run unix-socket benchmark as comparison */

		fds[0].fd = uds[0];
		fds[1].fd = uds[1];

		/* cancel any pendign message */
		read(uds[1], buf, sizeof(buf));

		start = now();
		reset_stats();

		send_ns = now();
		ret = write(uds[0], stress_payload, sizeof(stress_payload));
		ASSERT_RETURN(ret == sizeof(stress_payload));

		while (1) {
			unsigned int nfds = sizeof(fds) / sizeof(fds[0]);
			unsigned int i;

			for (i = 0; i < nfds; i++) {
				fds[i].events = POLLIN | POLLPRI | POLLHUP;
				fds[i].revents = 0;
			}

			ret = poll(fds, nfds, 10);
			if (ret < 0)
				break;

			if (fds[1].revents & POLLIN) {
				ret = read(uds[1], buf, sizeof(buf));
				ASSERT_RETURN(ret == sizeof(buf));
				add_stats(send_ns);

				send_ns = now();
				ret = write(uds[0], buf, sizeof(buf));
				ASSERT_RETURN(ret == sizeof(buf));
			}

			now_ns = now();
			diff = now_ns - start;
			if (diff > 1000000000ULL) {
				start = now_ns;

				dump_stats(true);
				reset_stats();

				break;
			}
		}

	} while (kdbus_util_verbose);

	kdbus_printf("-- closing bus connections\n");

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return (stats.count > 1) ? TEST_OK : TEST_ERR;
}
