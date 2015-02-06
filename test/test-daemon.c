#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <stdbool.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

int kdbus_test_daemon(struct kdbus_test_env *env)
{
	struct pollfd fds[2];
	int count;
	int ret;

	/* This test doesn't make any sense in non-interactive mode */
	if (!kdbus_util_verbose)
		return TEST_OK;

	printf("Created connection %llu on bus '%s'\n",
		(unsigned long long) env->conn->id, env->buspath);

	ret = kdbus_name_acquire(env->conn, "com.example.kdbus-test", NULL);
	ASSERT_RETURN(ret == 0);
	printf("  Aquired name: com.example.kdbus-test\n");

	fds[0].fd = env->conn->fd;
	fds[1].fd = STDIN_FILENO;

	printf("Monitoring connections:\n");

	for (count = 0;; count++) {
		int i, nfds = sizeof(fds) / sizeof(fds[0]);

		for (i = 0; i < nfds; i++) {
			fds[i].events = POLLIN | POLLPRI | POLLHUP;
			fds[i].revents = 0;
		}

		ret = poll(fds, nfds, -1);
		if (ret <= 0)
			break;

		if (fds[0].revents & POLLIN) {
			ret = kdbus_msg_recv(env->conn, NULL, NULL);
			ASSERT_RETURN(ret == 0);
		}

		/* stdin */
		if (fds[1].revents & POLLIN)
			break;
	}

	printf("Closing bus connection\n");

	return TEST_OK;
}
