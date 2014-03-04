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
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

struct pcap_header {
	uint32_t	magic;
	uint16_t	major;
	uint16_t	minor;
	uint32_t	tz_offset;
	uint32_t	ts_accurancy;
	uint32_t	snapshot_len;
	uint32_t	header_type;
};

struct pcap_entry {
	uint32_t	tv_sec;
	uint32_t	tv_usec;
	uint32_t	len;
	uint32_t	total_len;
	uint8_t		data[0];
};

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s <bus-node> <output-file>\n", argv0);
	fprintf(stderr, "       bus-node        The device node to connect to\n");
	fprintf(stderr, "       output-file     The output file to write to\n");
}

static int dump_packet(struct conn *conn, int fd)
{
	int ret;
	struct kdbus_cmd_recv recv = {};
	uint64_t size;
	struct kdbus_msg *msg;
	const struct kdbus_item *item;
	struct timeval now;
	struct pcap_entry entry;
	uint64_t to_write;
	void *data_to_write;

	gettimeofday(&now, NULL);
	entry.tv_sec = now.tv_sec;
	entry.tv_usec = now.tv_usec;

	ret = ioctl(conn->fd, KDBUS_CMD_MSG_RECV, &recv);
	if (ret < 0) {
		fprintf(stderr, "error receiving message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	msg = (struct kdbus_msg *)(conn->buf + recv.offset);
	item = msg->items;
	size = msg->size;

	/* collect length of oob payloads */
	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == KDBUS_ITEM_PAYLOAD_OFF)
			size += KDBUS_ALIGN8(item->vec.size);

	entry.len = size;
	entry.total_len = size;

	size = write(fd, &entry, sizeof(entry));
	if (size != sizeof(entry)) {
		fprintf(stderr, "Unable to write: %m\n");
		return EXIT_FAILURE;
	}

	size = write(fd, msg, msg->size);
	if (size != msg->size) {
		fprintf(stderr, "Unable to write: %m\n");
		return EXIT_FAILURE;
	}

	KDBUS_ITEM_FOREACH(item, msg, items) {
		switch (item->type) {
		/* close all memfds */
		case KDBUS_ITEM_PAYLOAD_MEMFD:
			close(item->memfd.fd);
			break;
		case KDBUS_ITEM_PAYLOAD_OFF:
			if (item->vec.offset != ~0ULL) {
				to_write = KDBUS_ALIGN8(item->vec.size);
				data_to_write = (void *) msg + item->vec.offset;
			} else {
				/*add data padding to file*/
				to_write = item->vec.size % 8;
				data_to_write = "\0\0\0\0\0\0\0";
			}

			size = write(fd, data_to_write, to_write);
			if (size != to_write) {
				fprintf(stderr, "Unable to write: %m\n");
				return EXIT_FAILURE;
			}
			break;
		}
	}

	ret = ioctl(conn->fd, KDBUS_CMD_FREE, &recv.offset);
	if (ret < 0) {
		fprintf(stderr, "error free message: %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	return 0;
}

static bool do_exit = false;

static void sig_handler(int foo)
{
	do_exit = true;
}

int main(int argc, char **argv)
{
	unsigned long long count = 0;
	struct sigaction act = {};
	struct pcap_header header;
	struct conn *conn;
	struct pollfd fd;
	char *bus, *file;
	sigset_t mask;
	int output_fd;
	int ret;

	if (argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	bus = argv[1];
	file = argv[2];

	output_fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (output_fd < 0) {
		fprintf(stderr, "Unable to open '%s': %m\n", file);
		return EXIT_FAILURE;
	}

	conn = kdbus_hello(bus, KDBUS_HELLO_MONITOR);
	if (!conn) {
		fprintf(stderr, "Unable to connect as monitor: %m\n");
		return EXIT_FAILURE;
	}

	memset(&header, 0, sizeof(header));
	header.magic = 0xa1b2c3d4;
	header.major = 2;
	header.minor = 4;
	header.snapshot_len = 0xffffffff;
	header.header_type = 0x12345678;			/* FIXME */

	ret = write(output_fd, &header, sizeof(header));
	if (ret != sizeof(header)) {
		fprintf(stderr, "Unable to write to '%s': %m\n", file);
		return EXIT_FAILURE;
	}

	act.sa_handler = sig_handler;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	fprintf(stderr, "Capturing. Press ^C to stop ...\n");

	fd.fd = conn->fd;

	while (!do_exit) {
		fd.events = POLLIN | POLLPRI | POLLHUP;
		fd.revents = 0;

		ret = poll(&fd, 1, -1);
		if (ret < 0)
			break;

		if (fd.revents & POLLIN) {
			ret = dump_packet(conn, output_fd);
			if (ret != 0) {
				fprintf(stderr, "Unable to dump packet '%s': %m\n", file);
				return EXIT_FAILURE;
			}

			count++;
		}

		if (fd.revents & (POLLHUP | POLLERR))
			do_exit = true;
	}

	fprintf(stderr, "\n%llu packets received and dumped.\n", count);
	fprintf(stderr, "-- closing bus connections\n");
	close(output_fd);
	close(conn->fd);
	free(conn);

	return 0;
}
