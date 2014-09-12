#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
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

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#define SERVICE_NAME "foo.bar.echo"

static char stress_payload[8192];

struct stats {
	uint64_t count;
	uint64_t latency_acc;
	uint64_t latency_low;
	uint64_t latency_high;
};

static struct stats stats;

static uint64_t
timeval_diff(const struct timeval *hi, const struct timeval *lo)
{
	struct timeval r;

	timersub(hi, lo, &r);

	return (uint64_t) (r.tv_sec * 1000000ULL) + (uint64_t) r.tv_usec;
}

static void reset_stats(void)
{
	stats.count = 0;
	stats.latency_acc = 0;
	stats.latency_low = UINT64_MAX;
	stats.latency_high = 0;
}

static void dump_stats(void)
{
	if (stats.count > 0) {
		kdbus_printf("stats: %llu packets processed, latency (usecs) min/max/avg %llu/%llu/%llu\n",
			     (unsigned long long) stats.count,
			     (unsigned long long) stats.latency_low,
			     (unsigned long long) stats.latency_high,
			     (unsigned long long) (stats.latency_acc / stats.count));
	} else {
		kdbus_printf("*** no packets received. bus stuck?\n");
	}
}

static void add_stats(const struct timeval *tv)
{
	struct timeval now;
	uint64_t diff;

	gettimeofday(&now, NULL);
	diff = timeval_diff(&now, tv);

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
	struct timeval now;

	gettimeofday(&now, NULL);

	size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	memfd = sys_memfd_create("memfd-name", 0);
	ASSERT_RETURN_VAL(memfd >= 0, memfd);

	ret = write(memfd, &now, sizeof(now));
	ASSERT_RETURN_VAL(ret == sizeof(now), -EAGAIN);

	ret = sys_memfd_seal_set(memfd);
	ASSERT_RETURN_VAL(ret == 0, -errno);

	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));

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

	item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_memfd);
	item->memfd.size = sizeof(struct timeval);
	item->memfd.fd = memfd;
	item = KDBUS_ITEM_NEXT(item);

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_SEND, msg);
	ASSERT_RETURN_VAL(ret == 0, -errno);

	close(memfd);
	free(msg);

	return 0;
}

static int
handle_echo_reply(struct kdbus_conn *conn)
{
	int ret;
	struct kdbus_cmd_recv recv = {};
	struct kdbus_msg *msg;
	const struct kdbus_item *item;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
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

			add_stats((struct timeval *) buf);
			munmap(buf, item->memfd.size);
			close(item->memfd.fd);
			break;
		}

		case KDBUS_ITEM_PAYLOAD_OFF: {
			/* ignore */
			break;
		}
		}
	}

	ret = kdbus_free(conn, recv.offset);
	ASSERT_RETURN_VAL(ret == 0, -errno);

	return 0;
}

int kdbus_test_benchmark(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_conn *conn_a, *conn_b;
	struct pollfd fds[2];
	struct timeval start;
	unsigned int i;

	for (i = 0; i < sizeof(stress_payload); i++)
		stress_payload[i] = i;

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	ret = kdbus_add_match_empty(conn_a);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(conn_b);
	ASSERT_RETURN(ret == 0);

	fds[0].fd = conn_a->fd;
	fds[1].fd = conn_b->fd;

	ret = kdbus_name_acquire(conn_a, SERVICE_NAME, 0);
	ASSERT_RETURN(ret == 0);

	gettimeofday(&start, NULL);
	reset_stats();

	ret = send_echo_request(conn_b, conn_a->id);
	ASSERT_RETURN(ret == 0);

	kdbus_printf("-- entering poll loop ...\n");

	while (1) {
		struct timeval now;
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
			ret = handle_echo_reply(conn_a);
			if (ret)
				break;

			ret = send_echo_request(conn_b, conn_a->id);
			if (ret)
				break;
		}

		gettimeofday(&now, NULL);
		if (timeval_diff(&now, &start) / 1000ULL > 1000ULL) {
			start.tv_sec = now.tv_sec;
			start.tv_usec = now.tv_usec;

			if (!env->verbose)
				break;

			dump_stats();
			reset_stats();
		}
	}

	kdbus_printf("-- closing bus connections\n");

	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return (stats.count > 10000) ? TEST_OK : TEST_ERR;
}
