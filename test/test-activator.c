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
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static int kdbus_starter_poll(struct kdbus_conn *conn)
{
	int ret;
	struct pollfd fd;

	fd.fd = conn->fd;
	fd.events = POLLIN | POLLPRI | POLLHUP;
	fd.revents = 0;

	ret = poll(&fd, 1, 100);
	if (ret == 0)
		return -ETIMEDOUT;
	else if (ret > 0) {
		if (fd.revents & POLLIN)
			return 0;

		if (fd.revents & (POLLHUP | POLLERR))
			ret = -ECONNRESET;
	}

	return ret;
}

/* Ensure that kdbus activator logic is safe */
static int kdbus_priv_activator(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_msg *msg = NULL;
	uint64_t cookie = 0xdeadbeef;
	uint64_t flags = KDBUS_NAME_REPLACE_EXISTING;
	struct kdbus_conn *activator;
	struct kdbus_conn *service;
	struct kdbus_conn *client;
	struct kdbus_conn *holder;
	struct kdbus_policy_access *access;

	access = (struct kdbus_policy_access[]){
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = getuid(),
			.access = KDBUS_POLICY_OWN,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = getuid(),
			.access = KDBUS_POLICY_TALK,
		},
	};

	activator = kdbus_hello_activator(env->buspath, "foo.priv.activator",
					  access, 2);
	ASSERT_RETURN(activator);

	service = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(service);

	client = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(client);

	/*
	 * Make sure that other users can't TALK to the activator
	 */

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		/* Try to talk using the ID */
		ret = kdbus_msg_send(unpriv, NULL, 0xdeadbeef, 0, 0,
				     0, activator->id);
		ASSERT_EXIT(ret == -ENXIO);

		/* Try to talk to the name */
		ret = kdbus_msg_send(unpriv, "foo.priv.activator",
				     0xdeadbeef, 0, 0, 0,
				     KDBUS_DST_ID_NAME);
		ASSERT_EXIT(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure that we did not receive anything, so the
	 * service will not be started automatically
	 */

	ret = kdbus_starter_poll(activator);
	ASSERT_RETURN(ret == -ETIMEDOUT);

	/*
	 * Now try to emulate the starter/service logic and
	 * acquire the name.
	 */

	cookie++;
	ret = kdbus_msg_send(service, "foo.priv.activator", cookie,
			     0, 0, 0, KDBUS_DST_ID_NAME);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_starter_poll(activator);
	ASSERT_RETURN(ret == 0);

	/* Policies are still checked, access denied */

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "foo.priv.activator",
					 &flags);
		ASSERT_RETURN(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_name_acquire(service, "foo.priv.activator",
				 &flags);
	ASSERT_RETURN(ret == 0);

	/* We read our previous starter message */

	ret = kdbus_msg_recv_poll(service, 100, NULL, NULL);
	ASSERT_RETURN(ret == 0);

	/* Try to talk, we still fail */

	cookie++;
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		/* Try to talk to the name */
		ret = kdbus_msg_send(unpriv, "foo.priv.activator",
				     cookie, 0, 0, 0,
				     KDBUS_DST_ID_NAME);
		ASSERT_EXIT(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	/* Still nothing to read */

	ret = kdbus_msg_recv_poll(service, 100, NULL, NULL);
	ASSERT_RETURN(ret == -ETIMEDOUT);

	/* We receive every thing now */

	cookie++;
	ret = kdbus_msg_send(client, "foo.priv.activator", cookie,
			     0, 0, 0, KDBUS_DST_ID_NAME);
	ASSERT_RETURN(ret == 0);
	ret = kdbus_msg_recv_poll(service, 100, &msg, NULL);
	ASSERT_RETURN(ret == 0 && msg->cookie == cookie);

	kdbus_msg_free(msg);

	/* Policies default to deny TALK now */
	kdbus_conn_free(activator);

	cookie++;
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		/* Try to talk to the name */
		ret = kdbus_msg_send(unpriv, "foo.priv.activator",
				     cookie, 0, 0, 0,
				     KDBUS_DST_ID_NAME);
		ASSERT_EXIT(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(service, 100, NULL, NULL);
	ASSERT_RETURN(ret == -ETIMEDOUT);

	/* Same user is able to TALK */
	cookie++;
	ret = kdbus_msg_send(client, "foo.priv.activator", cookie,
			     0, 0, 0, KDBUS_DST_ID_NAME);
	ASSERT_RETURN(ret == 0);
	ret = kdbus_msg_recv_poll(service, 100, &msg, NULL);
	ASSERT_RETURN(ret == 0 && msg->cookie == cookie);

	kdbus_msg_free(msg);

	access = (struct kdbus_policy_access []){
		{
			.type = KDBUS_POLICY_ACCESS_WORLD,
			.id = getuid(),
			.access = KDBUS_POLICY_TALK,
		},
	};

	holder = kdbus_hello_registrar(env->buspath, "foo.priv.activator",
				       access, 1, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(holder);

	/* Now we are able to TALK to the name */

	cookie++;
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		/* Try to talk to the name */
		ret = kdbus_msg_send(unpriv, "foo.priv.activator",
				     cookie, 0, 0, 0,
				     KDBUS_DST_ID_NAME);
		ASSERT_EXIT(ret == 0);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(service, 100, NULL, NULL);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "foo.priv.activator",
					 &flags);
		ASSERT_RETURN(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	kdbus_conn_free(service);
	kdbus_conn_free(client);
	kdbus_conn_free(holder);

	return 0;
}

int kdbus_test_activator(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_conn *activator;
	struct pollfd fds[2];
	bool activator_done = false;
	struct kdbus_policy_access access[2];

	access[0].type = KDBUS_POLICY_ACCESS_USER;
	access[0].id = getuid();
	access[0].access = KDBUS_POLICY_OWN;

	access[1].type = KDBUS_POLICY_ACCESS_WORLD;
	access[1].access = KDBUS_POLICY_TALK;

	activator = kdbus_hello_activator(env->buspath, "foo.test.activator",
					  access, 2);
	ASSERT_RETURN(activator);

	ret = kdbus_add_match_empty(env->conn);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_list(env->conn, KDBUS_LIST_NAMES |
				    KDBUS_LIST_UNIQUE |
				    KDBUS_LIST_ACTIVATORS |
				    KDBUS_LIST_QUEUED);
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

		ret = kdbus_list(env->conn, KDBUS_LIST_NAMES);
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

	/* Check if all uids/gids are mapped */
	if (!all_uids_gids_are_mapped())
		return TEST_SKIP;

	/* Check now capabilities, so we run the previous tests */
	ret = test_is_capable(CAP_SETUID, CAP_SETGID, -1);
	ASSERT_RETURN(ret >= 0);

	if (!ret)
		return TEST_SKIP;

	ret = kdbus_priv_activator(env);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(activator);

	return TEST_OK;
}
