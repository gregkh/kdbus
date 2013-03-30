#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>

#include "portal.h"

static struct umsg *create_message(int dst_id, char *string)
{
	struct umsg *msg;
	int string_size = strlen(string) + 1;

	msg = malloc(sizeof(*msg) + string_size);
	if (!msg) {
		fprintf(stderr, "No memory for message\n");
		exit(1);
	}
	msg->dst_id = dst_id;
	msg->size = string_size;
	strcpy(&msg->data[0], string);
	return msg;
}

static void print_message(struct umsg *msg)
{
	printf("message: dst_id=%d size=%d data=\"%s\"\n", msg->dst_id, msg->size, msg->data);
}

int main(int argc, char *argv[])
{
	int err;
	int fd1, fd2, fd3, fd4;
//	ssize_t count;
//	char string[100];
	struct umsg *msg;

	printf("-- opening portals\n");
	fd1 = open("/dev/portal1", O_RDWR|O_CLOEXEC);
	fd2 = open("/dev/portal2", O_RDWR|O_CLOEXEC);
	fd3 = open("/dev/portal3", O_RDWR|O_CLOEXEC);
	fd4 = open("/dev/portal4", O_RDWR|O_CLOEXEC);
	if ((fd1 < 0) ||
	    (fd2 < 0) ||
	    (fd3 < 0) ||
	    (fd4 < 0)) {
		fprintf(stderr, "Can't open all 4 portals\n");
		return EXIT_FAILURE;
	}


	printf("-- sending 1 message to portal 1, from portal 1\n");
	msg = create_message(1, "hello");malloc(sizeof(*msg) + 4000);
	err = ioctl(fd1, PORTAL_MSG_SEND, msg);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));
	free(msg);
	msg = create_message(1, "world");malloc(sizeof(*msg) + 4000);
	err = ioctl(fd1, PORTAL_MSG_SEND, msg);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));
	free(msg);

	printf("-- reading from portal 1\n");
//	count = read(fd1, &string[0], 100);
//	printf("--- count = %d, string = \"%s\"\n", (int)count, &string[0]);

	msg = create_message(20, "123456789012345678901234567890");
	err = ioctl(fd1, PORTAL_MSG_RECV, msg);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));
	else
		print_message(msg);
	err = ioctl(fd1, PORTAL_MSG_RECV, msg);
	if (err)
		printf("--- error %d \"%s\"\n", err, strerror(errno));
	else
		print_message(msg);
	free(msg);

	close(fd1);
	close(fd2);
	close(fd3);
	close(fd4);

	return EXIT_SUCCESS;
}
