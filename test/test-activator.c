#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <sys/ioctl.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

int kdbus_test_activator(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_conn *activator;
	struct pollfd fds[2];
	bool activator_done = false;
	struct kdbus_policy_access access[2];

	access[0].type = KDBUS_POLICY_ACCESS_USER;
	access[0].id = 1001;
	access[0].access = KDBUS_POLICY_OWN;

	access[1].type = KDBUS_POLICY_ACCESS_WORLD;
	access[1].access = KDBUS_POLICY_TALK;

	activator = kdbus_hello_activator(env->buspath, "foo.test.activator",
					  access, 2);
	ASSERT_RETURN(activator);

	ret = kdbus_add_match_empty(env->conn);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_list(env->conn, KDBUS_NAME_LIST_NAMES |
					 KDBUS_NAME_LIST_UNIQUE |
					 KDBUS_NAME_LIST_ACTIVATORS |
					 KDBUS_NAME_LIST_QUEUED);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_send(env->conn, "foo.test.activator", 0xdeafbeef,
			     0, 0, 0, KDBUS_DST_ID_NAME);
	ASSERT_RETURN(ret == 0);

	fds[0].fd = activator->fd;
	fds[1].fd = env->conn->fd;

	kdbus_printf("-- entering poll loop ...\n");

	for (;;) {
		int i, nfds = sizeof(fds) / sizeof(fds[0]);

		for (i = 0; i < nfds; i++) {
			fds[i].events = POLLIN | POLLPRI;
			fds[i].revents = 0;
		}

		ret = poll(fds, nfds, 3000);
		ASSERT_RETURN(ret >= 0);

		ret = kdbus_name_list(env->conn, KDBUS_NAME_LIST_NAMES);
		ASSERT_RETURN(ret == 0);

		if ((fds[0].revents & POLLIN) && !activator_done) {
			uint64_t flags = KDBUS_NAME_REPLACE_EXISTING;

			kdbus_printf("Starter was called back!\n");

			ret = kdbus_name_acquire(env->conn,
						 "foo.test.activator", &flags);
			ASSERT_RETURN(ret == 0);

			activator_done = true;
		}

		if (fds[1].revents & POLLIN) {
			kdbus_msg_recv(env->conn, NULL, NULL);
			break;
		}
	}

	kdbus_conn_free(activator);

	return TEST_OK;
}
