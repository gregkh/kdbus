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

int kdbus_test_chat(struct kdbus_test_env *env)
{
	int ret, cookie;
	struct kdbus_conn *conn_a, *conn_b;
	struct pollfd fds[2];
	uint64_t flags;
	int count;

	conn_a = kdbus_hello(env->buspath, 0, NULL, 0);
	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_a && conn_b);

	flags = KDBUS_NAME_ALLOW_REPLACEMENT;
	ret = kdbus_name_acquire(conn_a, "foo.bar.test", &flags);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(conn_a, "foo.bar.baz", NULL);
	ASSERT_RETURN(ret == 0);

	flags = KDBUS_NAME_QUEUE;
	ret = kdbus_name_acquire(conn_b, "foo.bar.baz", &flags);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(conn_a, "foo.bar.double", NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(conn_a, "foo.bar.double", NULL);
	ASSERT_RETURN(ret == -EALREADY);

	ret = kdbus_name_release(conn_a, "foo.bar.double");
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_release(conn_a, "foo.bar.double");
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_list(conn_b, KDBUS_LIST_UNIQUE |
				 KDBUS_LIST_NAMES  |
				 KDBUS_LIST_QUEUED |
				 KDBUS_LIST_ACTIVATORS);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(conn_a);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_add_match_empty(conn_b);
	ASSERT_RETURN(ret == 0);

	cookie = 0;
	ret = kdbus_msg_send(conn_b, NULL, 0xc0000000 | cookie, 0, 0, 0,
			     KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	fds[0].fd = conn_a->fd;
	fds[1].fd = conn_b->fd;

	kdbus_printf("-- entering poll loop ...\n");

	for (count = 0;; count++) {
		int i, nfds = sizeof(fds) / sizeof(fds[0]);

		for (i = 0; i < nfds; i++) {
			fds[i].events = POLLIN | POLLPRI | POLLHUP;
			fds[i].revents = 0;
		}

		ret = poll(fds, nfds, 3000);
		ASSERT_RETURN(ret >= 0);

		if (fds[0].revents & POLLIN) {
			if (count > 2)
				kdbus_name_release(conn_a, "foo.bar.baz");

			ret = kdbus_msg_recv(conn_a, NULL, NULL);
			ASSERT_RETURN(ret == 0);
			ret = kdbus_msg_send(conn_a, NULL,
					     0xc0000000 | cookie++,
					     0, 0, 0, conn_b->id);
			ASSERT_RETURN(ret == 0);
		}

		if (fds[1].revents & POLLIN) {
			ret = kdbus_msg_recv(conn_b, NULL, NULL);
			ASSERT_RETURN(ret == 0);
			ret = kdbus_msg_send(conn_b, NULL,
					     0xc0000000 | cookie++,
					     0, 0, 0, conn_a->id);
			ASSERT_RETURN(ret == 0);
		}

		ret = kdbus_list(conn_b, KDBUS_LIST_UNIQUE |
					 KDBUS_LIST_NAMES  |
					 KDBUS_LIST_QUEUED |
					 KDBUS_LIST_ACTIVATORS);
		ASSERT_RETURN(ret == 0);

		if (count > 10)
			break;
	}

	kdbus_printf("-- closing bus connections\n");
	kdbus_conn_free(conn_a);
	kdbus_conn_free(conn_b);

	return TEST_OK;
}
