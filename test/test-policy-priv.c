#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/wait.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static int test_policy_priv_by_id(const char *bus,
				  struct kdbus_conn *conn_dst,
				  bool drop_second_user,
				  int parent_status,
				  int child_status)
{
	int ret = 0;
	uint64_t expected_cookie = time(NULL) ^ 0xdeadbeef;

	ASSERT_RETURN(conn_dst);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, bus, ({
		ret = kdbus_msg_send(unpriv, NULL,
				     expected_cookie, 0, 0, 0,
				     conn_dst->id);
		ASSERT_EXIT(ret == child_status);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(conn_dst, 300, NULL, NULL);
	ASSERT_RETURN(ret == parent_status);

	return 0;
}

static int test_policy_priv_by_broadcast(const char *bus,
					 struct kdbus_conn *conn_dst,
					 int drop_second_user,
					 int parent_status,
					 int child_status)
{
	int efd;
	int ret = 0;
	eventfd_t event_status = 0;
	struct kdbus_msg *msg = NULL;
	uid_t second_uid = UNPRIV_UID;
	gid_t second_gid = UNPRIV_GID;
	struct kdbus_conn *child_2 = conn_dst;
	uint64_t expected_cookie = time(NULL) ^ 0xdeadbeef;

	/* Drop to another unprivileged user other than UNPRIV_UID */
	if (drop_second_user == DROP_OTHER_UNPRIV) {
		second_uid = UNPRIV_UID - 1;
		second_gid = UNPRIV_GID - 1;
	}

	/* child will signal parent to send broadcast */
	efd = eventfd(0, EFD_CLOEXEC);
	ASSERT_RETURN_VAL(efd >= 0, efd);

	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_GID, ({
		struct kdbus_conn *child;

		child = kdbus_hello(bus, 0, NULL, 0);
		ASSERT_EXIT(child);

		ret = kdbus_add_match_empty(child);
		ASSERT_EXIT(ret == 0);

		/* signal parent */
		ret = eventfd_write(efd, 1);
		ASSERT_EXIT(ret == 0);

		/* Use a little bit high time */
		ret = kdbus_msg_recv_poll(child, 500, &msg, NULL);
		ASSERT_EXIT(ret == child_status);

		/*
		 * If we expect the child to get the broadcast
		 * message, then check the received cookie.
		 */
		if (ret == 0) {
			ASSERT_EXIT(expected_cookie == msg->cookie);
		}

		/* Use expected_cookie since 'msg' might be NULL */
		ret = kdbus_msg_send(child, NULL, expected_cookie + 1,
				     0, 0, 0, KDBUS_DST_ID_BROADCAST);
		ASSERT_EXIT(ret == 0);

		kdbus_msg_free(msg);
		kdbus_conn_free(child);
	}),
	({
		if (drop_second_user == DO_NOT_DROP) {
			ASSERT_RETURN(child_2);

			ret = eventfd_read(efd, &event_status);
			ASSERT_RETURN(ret >= 0 && event_status == 1);

			ret = kdbus_msg_send(child_2, NULL,
					     expected_cookie, 0, 0, 0,
					     KDBUS_DST_ID_BROADCAST);
			ASSERT_RETURN(ret == 0);

			/* Use a little bit high time */
			ret = kdbus_msg_recv_poll(child_2, 1000,
						  &msg, NULL);
			ASSERT_RETURN(ret == parent_status);

			/*
			 * Check returned cookie in case we expect
			 * success.
			 */
			if (ret == 0) {
				ASSERT_RETURN(msg->cookie ==
					      expected_cookie + 1);
			}

			kdbus_msg_free(msg);
		} else {
			/*
			 * Two unprivileged users will try to
			 * communicate using broadcast.
			 */
			ret = RUN_UNPRIVILEGED(second_uid, second_gid, ({
				child_2 = kdbus_hello(bus, 0, NULL, 0);
				ASSERT_EXIT(child_2);

				ret = kdbus_add_match_empty(child_2);
				ASSERT_EXIT(ret == 0);

				ret = eventfd_read(efd, &event_status);
				ASSERT_EXIT(ret >= 0 && event_status == 1);

				ret = kdbus_msg_send(child_2, NULL,
						expected_cookie, 0, 0, 0,
						KDBUS_DST_ID_BROADCAST);
				ASSERT_EXIT(ret == 0);

				/* Use a little bit high time */
				ret = kdbus_msg_recv_poll(child_2, 1000,
							  &msg, NULL);
				ASSERT_EXIT(ret == parent_status);

				/*
				 * Check returned cookie in case we expect
				 * success.
				 */
				if (ret == 0) {
					ASSERT_EXIT(msg->cookie ==
						    expected_cookie + 1);
				}

				kdbus_msg_free(msg);
				kdbus_conn_free(child_2);
			}),
			({ 0; }));
			ASSERT_RETURN(ret == 0);
		}
	}));
	ASSERT_RETURN(ret == 0);

	close(efd);

	return ret;
}

static void nosig(int sig)
{
}

static int test_priv_before_policy_upload(struct kdbus_test_env *env)
{
	int ret = 0;
	struct kdbus_conn *conn;

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	/*
	 * Make sure unprivileged bus user cannot acquire names
	 * before registring any policy holder.
	 */

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret < 0);
	}));
	ASSERT_RETURN(ret == 0);

	/*
	 * Make sure unprivileged bus users cannot talk by default
	 * to privileged ones, unless a policy holder that allows
	 * this was uploaded.
	 */

	ret = test_policy_priv_by_id(env->buspath, conn, false,
				     -ETIMEDOUT, -EPERM);
	ASSERT_RETURN(ret == 0);

	/* Activate matching for a privileged connection */
	ret = kdbus_add_match_empty(conn);
	ASSERT_RETURN(ret == 0);

	/*
	 * First make sure that BROADCAST with msg flag
	 * KDBUS_MSG_EXPECT_REPLY will fail with -ENOTUNIQ
	 */
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, NULL, 0xdeadbeef,
				     KDBUS_MSG_EXPECT_REPLY,
				     5000000000ULL, 0,
				     KDBUS_DST_ID_BROADCAST);
		ASSERT_EXIT(ret == -ENOTUNIQ);
	}));
	ASSERT_RETURN(ret == 0);

	/*
	 * Test broadcast with a privileged connection.
	 *
	 * The first unprivileged receiver should not get the
	 * broadcast message sent by the privileged connection,
	 * since there is no a TALK policy that allows the
	 * unprivileged to TALK to the privileged connection. It
	 * will fail with -ETIMEDOUT
	 *
	 * Then second case:
	 * The privileged connection should get the broadcast
	 * message from the unprivileged one. Since the receiver is
	 * a privileged bus user and it has default TALK access to
	 * all connections it will receive those.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, conn,
					    DO_NOT_DROP,
					    0, -ETIMEDOUT);
	ASSERT_RETURN(ret == 0);


	/*
	 * Test broadcast with two unprivileged connections running
	 * under the same user.
	 *
	 * Both connections should succeed.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, NULL,
					    DROP_SAME_UNPRIV, 0, 0);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test broadcast with two unprivileged connections running
	 * under different users.
	 *
	 * Both connections will fail with -ETIMEDOUT.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, NULL,
					    DROP_OTHER_UNPRIV,
					    -ETIMEDOUT, -ETIMEDOUT);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(conn);

	return ret;
}

static int test_broadcast_after_policy_upload(struct kdbus_test_env *env)
{
	int ret;
	int efd;
	eventfd_t event_status = 0;
	struct kdbus_msg *msg = NULL;
	struct kdbus_conn *owner_a, *owner_b;
	struct kdbus_conn *holder_a, *holder_b;
	struct kdbus_policy_access access = {};
	uint64_t expected_cookie = time(NULL) ^ 0xdeadbeef;

	owner_a = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(owner_a);

	ret = kdbus_name_acquire(owner_a, "com.example.broadcastA", NULL);
	ASSERT_EXIT(ret >= 0);

	/*
	 * Make sure unprivileged bus users cannot talk by default
	 * to privileged ones, unless a policy holder that allows
	 * this was uploaded.
	 */

	++expected_cookie;
	ret = test_policy_priv_by_id(env->buspath, owner_a, false,
				     -ETIMEDOUT, -EPERM);
	ASSERT_RETURN(ret == 0);

	/*
	 * Make sure that privileged won't receive broadcasts unless
	 * it installs a match. It will fail with -ETIMEDOUT
	 *
	 * At same time check that the unprivileged connection will
	 * not receive the broadcast message from the privileged one
	 * since the privileged one owns a name with a restricted
	 * policy TALK (actually the TALK policy is still not
	 * registered so we fail by default), thus the unprivileged
	 * receiver is not able to TALK to that name.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, owner_a,
					    DO_NOT_DROP,
					    -ETIMEDOUT, -ETIMEDOUT);
	ASSERT_RETURN(ret == 0);

	/* Activate matching for a privileged connection */
	ret = kdbus_add_match_empty(owner_a);
	ASSERT_RETURN(ret == 0);

	/*
	 * Redo the previous test. The privileged conn owner_a is
	 * able to TALK to any connection so it will receive the
	 * broadcast message now.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, owner_a,
					    DO_NOT_DROP,
					    0, -ETIMEDOUT);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test that broadcast between two unprivileged users running
	 * under the same user still succeed.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, NULL,
					    DROP_SAME_UNPRIV, 0, 0);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test broadcast with two unprivileged connections running
	 * under different users.
	 *
	 * Both connections will fail with -ETIMEDOUT.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, NULL,
					    DROP_OTHER_UNPRIV,
					    -ETIMEDOUT, -ETIMEDOUT);
	ASSERT_RETURN(ret == 0);

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = geteuid(),
		.access = KDBUS_POLICY_OWN,
	};

	holder_a = kdbus_hello_registrar(env->buspath,
					 "com.example.broadcastA",
					 &access, 1,
					 KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(holder_a);

	holder_b = kdbus_hello_registrar(env->buspath,
					 "com.example.broadcastB",
					 &access, 1,
					 KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(holder_b);

	/* Free connections and their received messages and restart */
	kdbus_conn_free(owner_a);

	owner_a = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(owner_a);

	/* Activate matching for a privileged connection */
	ret = kdbus_add_match_empty(owner_a);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(owner_a, "com.example.broadcastA", NULL);
	ASSERT_EXIT(ret >= 0);

	owner_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(owner_b);

	ret = kdbus_name_acquire(owner_b, "com.example.broadcastB", NULL);
	ASSERT_EXIT(ret >= 0);

	/* Activate matching for a privileged connection */
	ret = kdbus_add_match_empty(owner_b);
	ASSERT_RETURN(ret == 0);

	/*
	 * Test that even if "com.example.broadcastA" and
	 * "com.example.broadcastB" do have a TALK access by default
	 * they are able to signal each other using broadcast due to
	 * the fact they are privileged connections, they receive
	 * all broadcasts if the match allows it.
	 */

	++expected_cookie;
	ret = kdbus_msg_send(owner_a, NULL, expected_cookie, 0,
			     0, 0, KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv_poll(owner_b, 100, &msg, NULL);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(msg->cookie == expected_cookie);

	/* Check src ID */
	ASSERT_RETURN(msg->src_id == owner_a->id);

	kdbus_msg_free(msg);

	/* Release name "com.example.broadcastB" */

	ret = kdbus_name_release(owner_b, "com.example.broadcastB");
	ASSERT_EXIT(ret >= 0);

	/* KDBUS_POLICY_OWN for unprivileged connections */
	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = geteuid(),
		.access = KDBUS_POLICY_OWN,
	};

	/* Update the policy so unprivileged will own the name */

	ret = kdbus_conn_update_policy(holder_b,
				       "com.example.broadcastB",
				       &access, 1);
	ASSERT_RETURN(ret == 0);

	/*
	 * Send broadcasts from an unprivileged connection that
	 * owns a name "com.example.broadcastB".
	 *
	 * We'll have four destinations here:
	 *
	 * 1) destination owner_a: privileged connection that owns
	 * "com.example.broadcastA". It will receive the broadcast
	 * since it is a privileged has default TALK access to all
	 * connections, and it is subscribed to the match.
	 * Will succeed.
	 *
	 * owner_b: privileged connection (running under a different
	 * uid) that do not own names, but with an empty broadcast
	 * match, so it will receive broadcasts since it has default
	 * TALK access to all connection.
	 *
	 * unpriv_a: unpriv connection that do not own any name.
	 * It will receive the broadcast since it is running under
	 * the same user of the one broadcasting and did install
	 * matches. It should get the message.
	 *
	 * unpriv_b: unpriv connection is not interested in broadcast
	 * messages, so it did not install broadcast matches. Should
	 * fail with -ETIMEDOUT
	 */

	++expected_cookie;
	efd = eventfd(0, EFD_CLOEXEC);
	ASSERT_RETURN_VAL(efd >= 0, efd);

	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_UID, ({
		struct kdbus_conn *unpriv_owner;
		struct kdbus_conn *unpriv_a, *unpriv_b;

		unpriv_owner = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_EXIT(unpriv_owner);

		unpriv_a = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_EXIT(unpriv_a);

		unpriv_b = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_EXIT(unpriv_b);

		ret = kdbus_name_acquire(unpriv_owner,
					 "com.example.broadcastB",
					 NULL);
		ASSERT_EXIT(ret >= 0);

		ret = kdbus_add_match_empty(unpriv_a);
		ASSERT_EXIT(ret == 0);

		/* Signal that we are doing broadcasts */
		ret = eventfd_write(efd, 1);
		ASSERT_EXIT(ret == 0);

		/*
		 * Do broadcast from a connection that owns the
		 * names "com.example.broadcastB".
		 */
		ret = kdbus_msg_send(unpriv_owner, NULL,
				     expected_cookie,
				     0, 0, 0,
				     KDBUS_DST_ID_BROADCAST);
		ASSERT_EXIT(ret == 0);

		/*
		 * Unprivileged connection running under the same
		 * user. It should succeed.
		 */
		ret = kdbus_msg_recv_poll(unpriv_a, 300, &msg, NULL);
		ASSERT_EXIT(ret == 0 && msg->cookie == expected_cookie);

		/*
		 * Did not install matches, not interested in
		 * broadcasts
		 */
		ret = kdbus_msg_recv_poll(unpriv_b, 300, NULL, NULL);
		ASSERT_EXIT(ret == -ETIMEDOUT);
	}),
	({
		ret = eventfd_read(efd, &event_status);
		ASSERT_RETURN(ret >= 0 && event_status == 1);

		/*
		 * owner_a must fail with -ETIMEDOUT, since it owns
		 * name "com.example.broadcastA" and its TALK
		 * access is restriced.
		 */
		ret = kdbus_msg_recv_poll(owner_a, 300, &msg, NULL);
		ASSERT_RETURN(ret == 0);

		/* confirm the received cookie */
		ASSERT_RETURN(msg->cookie == expected_cookie);

		kdbus_msg_free(msg);

		/*
		 * owner_b got the broadcast from an unprivileged
		 * connection.
		 */
		ret = kdbus_msg_recv_poll(owner_b, 300, &msg, NULL);
		ASSERT_RETURN(ret == 0);

		/* confirm the received cookie */
		ASSERT_RETURN(msg->cookie == expected_cookie);

		kdbus_msg_free(msg);

	}));
	ASSERT_RETURN(ret == 0);

	close(efd);

	/*
	 * Test broadcast with two unprivileged connections running
	 * under different users.
	 *
	 * Both connections will fail with -ETIMEDOUT.
	 */

	ret = test_policy_priv_by_broadcast(env->buspath, NULL,
					    DROP_OTHER_UNPRIV,
					    -ETIMEDOUT, -ETIMEDOUT);
	ASSERT_RETURN(ret == 0);

	/* Drop received broadcasts by privileged */
	ret = kdbus_msg_recv_poll(owner_a, 100, NULL, NULL);
	ret = kdbus_msg_recv_poll(owner_a, 100, NULL, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(owner_a, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	ret = kdbus_msg_recv_poll(owner_b, 100, NULL, NULL);
	ret = kdbus_msg_recv_poll(owner_b, 100, NULL, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_msg_recv(owner_b, NULL, NULL);
	ASSERT_RETURN(ret == -EAGAIN);

	/*
	 * Perform last tests, allow others to talk to name
	 * "com.example.broadcastA". So now receiving broadcasts
	 * from it should succeed since the TALK policy allow it.
	 */

	/* KDBUS_POLICY_OWN for unprivileged connections */
	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = geteuid(),
		.access = KDBUS_POLICY_TALK,
	};

	ret = kdbus_conn_update_policy(holder_a,
				       "com.example.broadcastA",
				       &access, 1);
	ASSERT_RETURN(ret == 0);

	/*
	 * Unprivileged is able to TALK to "com.example.broadcastA"
	 * now so it will receive its broadcasts
	 */
	ret = test_policy_priv_by_broadcast(env->buspath, owner_a,
					    DO_NOT_DROP, 0, 0);
	ASSERT_RETURN(ret == 0);

	++expected_cookie;
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.broadcastB",
					 NULL);
		ASSERT_EXIT(ret >= 0);
		ret = kdbus_msg_send(unpriv, NULL, expected_cookie,
				     0, 0, 0, KDBUS_DST_ID_BROADCAST);
		ASSERT_EXIT(ret == 0);
	}));
	ASSERT_RETURN(ret == 0);

	/* owner_a is privileged it will get the broadcast now. */
	ret = kdbus_msg_recv_poll(owner_a, 300, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	/* confirm the received cookie */
	ASSERT_RETURN(msg->cookie == expected_cookie);

	kdbus_msg_free(msg);

	/*
	 * owner_a released name "com.example.broadcastA". It should
	 * receive broadcasts since it is still privileged and has
	 * the right match.
	 *
	 * Unprivileged connection will own a name and will try to
	 * signal to the privileged connection.
	 */

	ret = kdbus_name_release(owner_a, "com.example.broadcastA");
	ASSERT_EXIT(ret >= 0);

	++expected_cookie;
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.broadcastB",
					 NULL);
		ASSERT_EXIT(ret >= 0);
		ret = kdbus_msg_send(unpriv, NULL, expected_cookie,
				     0, 0, 0, KDBUS_DST_ID_BROADCAST);
		ASSERT_EXIT(ret == 0);
	}));
	ASSERT_RETURN(ret == 0);

	/* owner_a will get the broadcast now. */
	ret = kdbus_msg_recv_poll(owner_a, 300, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	/* confirm the received cookie */
	ASSERT_RETURN(msg->cookie == expected_cookie);

	kdbus_msg_free(msg);

	kdbus_conn_free(owner_a);
	kdbus_conn_free(owner_b);
	kdbus_conn_free(holder_a);
	kdbus_conn_free(holder_b);

	return 0;
}

static int test_policy_priv(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_a, *conn_b, *conn, *owner;
	struct kdbus_policy_access access, *acc;
	sigset_t sset;
	size_t num;
	int ret;

	/*
	 * Make sure we have CAP_SETUID/SETGID so we can drop privileges
	 */

	ret = test_is_capable(CAP_SETUID, CAP_SETGID, -1);
	ASSERT_RETURN(ret >= 0);

	if (!ret)
		return TEST_SKIP;

	/* make sure that uids and gids are mapped */
	if (!all_uids_gids_are_mapped())
		return TEST_SKIP;

	/*
	 * Setup:
	 *  conn_a: policy holder for com.example.a
	 *  conn_b: name holder of com.example.b
	 */

	signal(SIGUSR1, nosig);
	sigemptyset(&sset);
	sigaddset(&sset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sset, NULL);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	/*
	 * Before registering any policy holder, make sure that the
	 * bus is secure by default. This test is necessary, it catches
	 * several cases where old D-Bus was vulnerable.
	 */

	ret = test_priv_before_policy_upload(env);
	ASSERT_RETURN(ret == 0);

	/*
	 * Make sure unprivileged are not able to register policy
	 * holders
	 */

	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_GID, ({
		struct kdbus_conn *holder;

		holder = kdbus_hello_registrar(env->buspath,
					       "com.example.a", NULL, 0,
					       KDBUS_HELLO_POLICY_HOLDER);
		ASSERT_EXIT(holder == NULL && errno == EPERM);
	}),
	({ 0; }));
	ASSERT_RETURN(ret == 0);


	/* Register policy holder */

	conn_a = kdbus_hello_registrar(env->buspath, "com.example.a",
				       NULL, 0, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(conn_a);

	conn_b = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn_b);

	ret = kdbus_name_acquire(conn_b, "com.example.b", NULL);
	ASSERT_EXIT(ret >= 0);

	/*
	 * Make sure bus-owners can always acquire names.
	 */
	ret = kdbus_name_acquire(conn, "com.example.a", NULL);
	ASSERT_EXIT(ret >= 0);

	kdbus_conn_free(conn);

	/*
	 * Make sure unprivileged users cannot acquire names with default
	 * policy assigned.
	 */

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret < 0);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged users can acquire names if we make them
	 * world-accessible.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = 0,
		.access = KDBUS_POLICY_OWN,
	};

	/*
	 * Make sure unprivileged/normal connections are not able
	 * to update policies
	 */

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_conn_update_policy(unpriv, "com.example.a",
					       &access, 1);
		ASSERT_EXIT(ret == -EOPNOTSUPP);
	}));
	ASSERT_RETURN(ret == 0);

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged users can acquire names if we make them
	 * gid-accessible. But only if the gid matches.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_GROUP,
		.id = UNPRIV_GID,
		.access = KDBUS_POLICY_OWN,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_GROUP,
		.id = 1,
		.access = KDBUS_POLICY_OWN,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret < 0);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged users can acquire names if we make them
	 * uid-accessible. But only if the uid matches.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = UNPRIV_UID,
		.access = KDBUS_POLICY_OWN,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = 1,
		.access = KDBUS_POLICY_OWN,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret < 0);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged users cannot acquire names if no owner-policy
	 * matches, even if SEE/TALK policies match.
	 */

	num = 4;
	acc = (struct kdbus_policy_access[]){
		{
			.type = KDBUS_POLICY_ACCESS_GROUP,
			.id = UNPRIV_GID,
			.access = KDBUS_POLICY_SEE,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = UNPRIV_UID,
			.access = KDBUS_POLICY_TALK,
		},
		{
			.type = KDBUS_POLICY_ACCESS_WORLD,
			.id = 0,
			.access = KDBUS_POLICY_TALK,
		},
		{
			.type = KDBUS_POLICY_ACCESS_WORLD,
			.id = 0,
			.access = KDBUS_POLICY_SEE,
		},
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", acc, num);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret < 0);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged users can acquire names if the only matching
	 * policy is somewhere in the middle.
	 */

	num = 5;
	acc = (struct kdbus_policy_access[]){
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 1,
			.access = KDBUS_POLICY_OWN,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 2,
			.access = KDBUS_POLICY_OWN,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = UNPRIV_UID,
			.access = KDBUS_POLICY_OWN,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 3,
			.access = KDBUS_POLICY_OWN,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 4,
			.access = KDBUS_POLICY_OWN,
		},
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", acc, num);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Clear policies
	 */

	ret = kdbus_conn_update_policy(conn_a, "com.example.a", NULL, 0);
	ASSERT_RETURN(ret == 0);

	/*
	 * Make sure privileged bus users can _always_ talk to others.
	 */

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_msg_send(conn, "com.example.b", 0xdeadbeef, 0, 0, 0, 0);
	ASSERT_EXIT(ret >= 0);

	ret = kdbus_msg_recv_poll(conn_b, 300, NULL, NULL);
	ASSERT_EXIT(ret >= 0);

	kdbus_conn_free(conn);

	/*
	 * Make sure unprivileged bus users cannot talk by default.
	 */

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged bus users can talk to equals, even without
	 * policy.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = UNPRIV_UID,
		.access = KDBUS_POLICY_OWN,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.c", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		struct kdbus_conn *owner;

		owner = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(owner);

		ret = kdbus_name_acquire(owner, "com.example.c", NULL);
		ASSERT_EXIT(ret >= 0);

		ret = kdbus_msg_send(unpriv, "com.example.c", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);
		ret = kdbus_msg_recv_poll(owner, 100, NULL, NULL);
		ASSERT_EXIT(ret >= 0);

		kdbus_conn_free(owner);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged bus users can talk to privileged users if a
	 * suitable UID policy is set.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_USER,
		.id = UNPRIV_UID,
		.access = KDBUS_POLICY_TALK,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.b", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(conn_b, 100, NULL, NULL);
	ASSERT_EXIT(ret >= 0);

	/*
	 * Make sure unprivileged bus users can talk to privileged users if a
	 * suitable GID policy is set.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_GROUP,
		.id = UNPRIV_GID,
		.access = KDBUS_POLICY_TALK,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.b", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(conn_b, 100, NULL, NULL);
	ASSERT_EXIT(ret >= 0);

	/*
	 * Make sure unprivileged bus users can talk to privileged users if a
	 * suitable WORLD policy is set.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = 0,
		.access = KDBUS_POLICY_TALK,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.b", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(conn_b, 100, NULL, NULL);
	ASSERT_EXIT(ret >= 0);

	/*
	 * Make sure unprivileged bus users cannot talk to privileged users if
	 * no suitable policy is set.
	 */

	num = 5;
	acc = (struct kdbus_policy_access[]){
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 0,
			.access = KDBUS_POLICY_OWN,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 1,
			.access = KDBUS_POLICY_TALK,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = UNPRIV_UID,
			.access = KDBUS_POLICY_SEE,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 3,
			.access = KDBUS_POLICY_TALK,
		},
		{
			.type = KDBUS_POLICY_ACCESS_USER,
			.id = 4,
			.access = KDBUS_POLICY_TALK,
		},
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.b", acc, num);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure unprivileged bus users can talk to privileged users if a
	 * suitable OWN privilege overwrites TALK.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = 0,
		.access = KDBUS_POLICY_OWN,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.b", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);
	}));
	ASSERT_RETURN(ret >= 0);

	ret = kdbus_msg_recv_poll(conn_b, 100, NULL, NULL);
	ASSERT_EXIT(ret >= 0);

	/*
	 * Make sure the TALK cache is reset correctly when policies are
	 * updated.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = 0,
		.access = KDBUS_POLICY_TALK,
	};

	ret = kdbus_conn_update_policy(conn_a, "com.example.b", &access, 1);
	ASSERT_RETURN(ret == 0);

	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);

		ret = kdbus_msg_recv_poll(conn_b, 100, NULL, NULL);
		ASSERT_EXIT(ret >= 0);

		ret = kdbus_conn_update_policy(conn_a, "com.example.b",
					       NULL, 0);
		ASSERT_RETURN(ret == 0);

		ret = kdbus_msg_send(unpriv, "com.example.b", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret == -EPERM);
	}));
	ASSERT_RETURN(ret >= 0);

	/*
	 * Make sure the TALK cache is reset correctly when policy holders
	 * disconnect.
	 */

	access = (struct kdbus_policy_access){
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = 0,
		.access = KDBUS_POLICY_OWN,
	};

	conn = kdbus_hello_registrar(env->buspath, "com.example.c",
				     NULL, 0, KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(conn);

	ret = kdbus_conn_update_policy(conn, "com.example.c", &access, 1);
	ASSERT_RETURN(ret == 0);

	owner = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(owner);

	ret = kdbus_name_acquire(owner, "com.example.c", NULL);
	ASSERT_RETURN(ret >= 0);

	ret = RUN_UNPRIVILEGED(UNPRIV_UID, UNPRIV_GID, ({
		struct kdbus_conn *unpriv;

		/* wait for parent to be finished */
		sigemptyset(&sset);
		ret = sigsuspend(&sset);
		ASSERT_RETURN(ret == -1 && errno == EINTR);

		unpriv = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(unpriv);

		ret = kdbus_msg_send(unpriv, "com.example.c", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret >= 0);

		ret = kdbus_msg_recv_poll(owner, 100, NULL, NULL);
		ASSERT_EXIT(ret >= 0);

		/* free policy holder */
		kdbus_conn_free(conn);

		ret = kdbus_msg_send(unpriv, "com.example.c", 0xdeadbeef, 0, 0,
				     0, 0);
		ASSERT_EXIT(ret == -EPERM);

		kdbus_conn_free(unpriv);
	}), ({
		/* make sure policy holder is only valid in child */
		kdbus_conn_free(conn);
		kill(pid, SIGUSR1);
	}));
	ASSERT_RETURN(ret >= 0);


	/*
	 * The following tests are necessary.
	 */

	ret = test_broadcast_after_policy_upload(env);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(owner);

	/*
	 * cleanup resources
	 */

	kdbus_conn_free(conn_b);
	kdbus_conn_free(conn_a);

	return TEST_OK;
}

int kdbus_test_policy_priv(struct kdbus_test_env *env)
{
	pid_t pid;
	int ret;

	/* make sure to exit() if a child returns from fork() */
	pid = getpid();
	ret = test_policy_priv(env);
	if (pid != getpid())
		exit(1);

	return ret;
}
