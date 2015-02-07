/*
 * Test metadata and policies in new namespaces. Even if our tests
 * can run in a namespaced setup, this test is necessary so we can
 * inspect policies on the same kdbusfs but between multiple
 * namespaces.
 *
 * Copyright (C) 2014-2015 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <linux/sched.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#define MAX_CONN	64
#define POLICY_NAME	"foo.test.policy-test"

#define KDBUS_CONN_MAX_MSGS_PER_USER            16

/**
 * Note: this test can be used to inspect policy_db->talk_access_hash
 *
 * The purpose of these tests:
 * 1) Check KDBUS_POLICY_TALK
 * 2) Check the cache state: kdbus_policy_db->talk_access_hash
 * Should be extended
 */

/**
 * Check a list of connections against conn_db[0]
 * conn_db[0] will own the name "foo.test.policy-test" and the
 * policy holder connection for this name will update the policy
 * entries, so different use cases can be tested.
 */
static struct kdbus_conn **conn_db;

static void *kdbus_recv_echo(void *ptr)
{
	int ret;
	struct kdbus_conn *conn = ptr;

	ret = kdbus_msg_recv_poll(conn, 200, NULL, NULL);

	return (void *)(long)ret;
}

/* Trigger kdbus_policy_set() */
static int kdbus_set_policy_talk(struct kdbus_conn *conn,
				 const char *name,
				 uid_t id, unsigned int type)
{
	int ret;
	struct kdbus_policy_access access = {
		.type = type,
		.id = id,
		.access = KDBUS_POLICY_TALK,
	};

	ret = kdbus_conn_update_policy(conn, name, &access, 1);
	ASSERT_RETURN(ret == 0);

	return TEST_OK;
}

/* return TEST_OK or TEST_ERR on failure */
static int kdbus_register_same_activator(char *bus, const char *name,
					 struct kdbus_conn **c)
{
	int ret;
	struct kdbus_conn *activator;

	activator = kdbus_hello_activator(bus, name, NULL, 0);
	if (activator) {
		*c = activator;
		fprintf(stderr, "--- error was able to register name twice '%s'.\n",
			name);
		return TEST_ERR;
	}

	ret = -errno;
	/* -EEXIST means test succeeded */
	if (ret == -EEXIST)
		return TEST_OK;

	return TEST_ERR;
}

/* return TEST_OK or TEST_ERR on failure */
static int kdbus_register_policy_holder(char *bus, const char *name,
					struct kdbus_conn **conn)
{
	struct kdbus_conn *c;
	struct kdbus_policy_access access[2];

	access[0].type = KDBUS_POLICY_ACCESS_USER;
	access[0].access = KDBUS_POLICY_OWN;
	access[0].id = geteuid();

	access[1].type = KDBUS_POLICY_ACCESS_WORLD;
	access[1].access = KDBUS_POLICY_TALK;
	access[1].id = geteuid();

	c = kdbus_hello_registrar(bus, name, access, 2,
				  KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(c);

	*conn = c;

	return TEST_OK;
}

/**
 * Create new threads for receiving from multiple senders,
 * The 'conn_db' will be populated by newly created connections.
 * Caller should free all allocated connections.
 *
 * return 0 on success, negative errno on failure.
 */
static int kdbus_recv_in_threads(const char *bus, const char *name,
				 struct kdbus_conn **conn_db)
{
	int ret;
	bool pool_full = false;
	unsigned int sent_packets = 0;
	unsigned int lost_packets = 0;
	unsigned int i, tid;
	unsigned long dst_id;
	unsigned long cookie = 1;
	unsigned int thread_nr = MAX_CONN - 1;
	pthread_t thread_id[MAX_CONN - 1] = {'\0'};

	dst_id = name ? KDBUS_DST_ID_NAME : conn_db[0]->id;

	for (tid = 0, i = 1; tid < thread_nr; tid++, i++) {
		ret = pthread_create(&thread_id[tid], NULL,
				     kdbus_recv_echo, (void *)conn_db[0]);
		if (ret < 0) {
			ret = -errno;
			kdbus_printf("error pthread_create: %d (%m)\n",
				      ret);
			break;
		}

		/* just free before re-using */
		kdbus_conn_free(conn_db[i]);
		conn_db[i] = NULL;

		/* We need to create connections here */
		conn_db[i] = kdbus_hello(bus, 0, NULL, 0);
		if (!conn_db[i]) {
			ret = -errno;
			break;
		}

		ret = kdbus_add_match_empty(conn_db[i]);
		if (ret < 0)
			break;

		ret = kdbus_msg_send(conn_db[i], name, cookie++,
				     0, 0, 0, dst_id);
		if (ret < 0) {
			/*
			 * Receivers are not reading their messages,
			 * not scheduled ?!
			 *
			 * So set the pool full here, perhaps the
			 * connection pool or queue was full, later
			 * recheck receivers errors
			 */
			if (ret == -ENOBUFS || ret == -EXFULL)
				pool_full = true;
			break;
		}

		sent_packets++;
	}

	for (tid = 0; tid < thread_nr; tid++) {
		int thread_ret = 0;

		if (thread_id[tid]) {
			pthread_join(thread_id[tid], (void *)&thread_ret);
			if (thread_ret < 0) {
				/* Update only if send did not fail */
				if (ret == 0)
					ret = thread_ret;

				lost_packets++;
			}
		}
	}

	/*
	 * When sending if we did fail with -ENOBUFS or -EXFULL
	 * then we should have set lost_packet and we should at
	 * least have sent_packets set to KDBUS_CONN_MAX_MSGS_PER_USER
	 */
	if (pool_full) {
		ASSERT_RETURN(lost_packets > 0);

		/*
		 * We should at least send KDBUS_CONN_MAX_MSGS_PER_USER
		 *
		 * For every send operation we create a thread to
		 * recv the packet, so we keep the queue clean
		 */
		ASSERT_RETURN(sent_packets >= KDBUS_CONN_MAX_MSGS_PER_USER);

		/*
		 * Set ret to zero since we only failed due to
		 * the receiving threads that have not been
		 * scheduled
		 */
		ret = 0;
	}

	return ret;
}

/* Return: TEST_OK or TEST_ERR on failure */
static int kdbus_normal_test(const char *bus, const char *name,
			     struct kdbus_conn **conn_db)
{
	int ret;

	ret = kdbus_recv_in_threads(bus, name, conn_db);
	ASSERT_RETURN(ret >= 0);

	return TEST_OK;
}

static int kdbus_fork_test_by_id(const char *bus,
				 struct kdbus_conn **conn_db,
				 int parent_status, int child_status)
{
	int ret;
	pid_t pid;
	uint64_t cookie = 0x9876ecba;
	struct kdbus_msg *msg = NULL;
	uint64_t offset = 0;
	int status = 0;

	/*
	 * If the child_status is not EXIT_SUCCESS, then we expect
	 * that sending from the child will fail, thus receiving
	 * from parent must error with -ETIMEDOUT, and vice versa.
	 */
	bool parent_timedout = !!child_status;
	bool child_timedout = !!parent_status;

	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, pid);

	if (pid == 0) {
		struct kdbus_conn *conn_src;

		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		ASSERT_EXIT(ret == 0);

		ret = drop_privileges(65534, 65534);
		ASSERT_EXIT(ret == 0);

		conn_src = kdbus_hello(bus, 0, NULL, 0);
		ASSERT_EXIT(conn_src);

		ret = kdbus_add_match_empty(conn_src);
		ASSERT_EXIT(ret == 0);

		/*
		 * child_status is always checked against send
		 * operations, in case it fails always return
		 * EXIT_FAILURE.
		 */
		ret = kdbus_msg_send(conn_src, NULL, cookie,
				     0, 0, 0, conn_db[0]->id);
		ASSERT_EXIT(ret == child_status);

		ret = kdbus_msg_recv_poll(conn_src, 100, NULL, NULL);

		kdbus_conn_free(conn_src);

		/*
		 * Child kdbus_msg_recv_poll() should timeout since
		 * the parent_status was set to a non EXIT_SUCCESS
		 * value.
		 */
		if (child_timedout)
			_exit(ret == -ETIMEDOUT ? EXIT_SUCCESS : EXIT_FAILURE);

		_exit(ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	ret = kdbus_msg_recv_poll(conn_db[0], 100, &msg, &offset);
	/*
	 * If parent_timedout is set then this should fail with
	 * -ETIMEDOUT since the child_status was set to a non
	 * EXIT_SUCCESS value. Otherwise, assume
	 * that kdbus_msg_recv_poll() has succeeded.
	 */
	if (parent_timedout) {
		ASSERT_RETURN_VAL(ret == -ETIMEDOUT, TEST_ERR);

		/* timedout no need to continue, we don't have the
		 * child connection ID, so just terminate. */
		goto out;
	} else {
		ASSERT_RETURN_VAL(ret == 0, ret);
	}

	ret = kdbus_msg_send(conn_db[0], NULL, ++cookie,
			     0, 0, 0, msg->src_id);
	/*
	 * parent_status is checked against send operations,
	 * on failures always return TEST_ERR.
	 */
	ASSERT_RETURN_VAL(ret == parent_status, TEST_ERR);

	kdbus_msg_free(msg);
	kdbus_free(conn_db[0], offset);

out:
	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN_VAL(ret >= 0, ret);

	return (status == EXIT_SUCCESS) ? TEST_OK : TEST_ERR;
}

/*
 * Return: TEST_OK, TEST_ERR or TEST_SKIP
 * we return TEST_OK only if the children return with the expected
 * 'expected_status' that is specified as an argument.
 */
static int kdbus_fork_test(const char *bus, const char *name,
			   struct kdbus_conn **conn_db, int expected_status)
{
	pid_t pid;
	int ret = 0;
	int status = 0;

	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, pid);

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		ASSERT_EXIT(ret == 0);

		ret = drop_privileges(65534, 65534);
		ASSERT_EXIT(ret == 0);

		ret = kdbus_recv_in_threads(bus, name, conn_db);
		_exit(ret == expected_status ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN(ret >= 0);

	return (status == EXIT_SUCCESS) ? TEST_OK : TEST_ERR;
}

/* Return EXIT_SUCCESS, EXIT_FAILURE or negative errno */
static int __kdbus_clone_userns_test(const char *bus,
				     const char *name,
				     struct kdbus_conn **conn_db,
				     int expected_status)
{
	int efd;
	pid_t pid;
	int ret = 0;
	unsigned int uid = 65534;
	int status;

	ret = drop_privileges(uid, uid);
	ASSERT_RETURN_VAL(ret == 0, ret);

	/*
	 * Since we just dropped privileges, the dumpable flag was just
	 * cleared which makes the /proc/$clone_child/uid_map to be
	 * owned by root, hence any userns uid mapping will fail with
	 * -EPERM since the mapping will be done by uid 65534.
	 *
	 * To avoid this set the dumpable flag again which makes procfs
	 * update the /proc/$clone_child/ inodes owner to 65534.
	 *
	 * Using this we will be able write to /proc/$clone_child/uid_map
	 * as uid 65534 and map the uid 65534 to 0 inside the user
	 * namespace.
	 */
	ret = prctl(PR_SET_DUMPABLE, SUID_DUMP_USER);
	ASSERT_RETURN_VAL(ret == 0, ret);

	/* sync parent/child */
	efd = eventfd(0, EFD_CLOEXEC);
	ASSERT_RETURN_VAL(efd >= 0, efd);

	pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWUSER, NULL);
	if (pid < 0) {
		ret = -errno;
		kdbus_printf("error clone: %d (%m)\n", ret);
		/*
		 * Normal user not allowed to create userns,
		 * so nothing to worry about ?
		 */
		if (ret == -EPERM) {
			kdbus_printf("-- CLONE_NEWUSER TEST Failed for uid: %u\n"
				"-- Make sure that your kernel do not allow "
				"CLONE_NEWUSER for unprivileged users\n"
				"-- Upstream Commit: "
				"https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=5eaf563e\n",
				uid);
			ret = 0;
		}

		return ret;
	}

	if (pid == 0) {
		struct kdbus_conn *conn_src;
		eventfd_t event_status = 0;

		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		ASSERT_EXIT(ret == 0);

		ret = eventfd_read(efd, &event_status);
		ASSERT_EXIT(ret >= 0 && event_status == 1);

		/* ping connection from the new user namespace */
		conn_src = kdbus_hello(bus, 0, NULL, 0);
		ASSERT_EXIT(conn_src);

		ret = kdbus_add_match_empty(conn_src);
		ASSERT_EXIT(ret == 0);

		ret = kdbus_msg_send(conn_src, name, 0xabcd1234,
				     0, 0, 0, KDBUS_DST_ID_NAME);
		kdbus_conn_free(conn_src);

		_exit(ret == expected_status ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	ret = userns_map_uid_gid(pid, "0 65534 1", "0 65534 1");
	ASSERT_RETURN_VAL(ret == 0, ret);

	/* Tell child we are ready */
	ret = eventfd_write(efd, 1);
	ASSERT_RETURN_VAL(ret == 0, ret);

	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN_VAL(ret >= 0, ret);

	close(efd);

	return status == EXIT_SUCCESS ? TEST_OK : TEST_ERR;
}

static int kdbus_clone_userns_test(const char *bus,
				   const char *name,
				   struct kdbus_conn **conn_db,
				   int expected_status)
{
	pid_t pid;
	int ret = 0;
	int status;

	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, -errno);

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0)
			_exit(EXIT_FAILURE);

		ret = __kdbus_clone_userns_test(bus, name, conn_db,
						expected_status);
		_exit(ret);
	}

	/*
	 * Receive in the original (root privileged) user namespace,
	 * must fail with -ETIMEDOUT.
	 */
	ret = kdbus_msg_recv_poll(conn_db[0], 100, NULL, NULL);
	ASSERT_RETURN_VAL(ret == -ETIMEDOUT, ret);

	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN_VAL(ret >= 0, ret);

	return (status == EXIT_SUCCESS) ? TEST_OK : TEST_ERR;
}

int kdbus_test_policy_ns(struct kdbus_test_env *env)
{
	int i;
	int ret;
	struct kdbus_conn *activator = NULL;
	struct kdbus_conn *policy_holder = NULL;
	char *bus = env->buspath;

	ret = test_is_capable(CAP_SETUID, CAP_SETGID, -1);
	ASSERT_RETURN(ret >= 0);

	/* no enough privileges, SKIP test */
	if (!ret)
		return TEST_SKIP;

	/* we require user-namespaces */
	if (access("/proc/self/uid_map", F_OK) != 0)
		return TEST_SKIP;

	/* uids/gids must be mapped */
	if (!all_uids_gids_are_mapped())
		return TEST_SKIP;

	conn_db = calloc(MAX_CONN, sizeof(struct kdbus_conn *));
	ASSERT_RETURN(conn_db);

	memset(conn_db, 0, MAX_CONN * sizeof(struct kdbus_conn *));

	conn_db[0] = kdbus_hello(bus, 0, NULL, 0);
	ASSERT_RETURN(conn_db[0]);

	ret = kdbus_add_match_empty(conn_db[0]);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_fork_test_by_id(bus, conn_db, -EPERM, -EPERM);
	ASSERT_EXIT(ret == 0);

	ret = kdbus_register_policy_holder(bus, POLICY_NAME,
					   &policy_holder);
	ASSERT_RETURN(ret == 0);

	/* Try to register the same name with an activator */
	ret = kdbus_register_same_activator(bus, POLICY_NAME,
					    &activator);
	ASSERT_RETURN(ret == 0);

	/* Acquire POLICY_NAME */
	ret = kdbus_name_acquire(conn_db[0], POLICY_NAME, NULL);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_normal_test(bus, POLICY_NAME, conn_db);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_list(conn_db[0], KDBUS_LIST_NAMES |
				     KDBUS_LIST_UNIQUE |
				     KDBUS_LIST_ACTIVATORS |
				     KDBUS_LIST_QUEUED);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_fork_test(bus, POLICY_NAME, conn_db, EXIT_SUCCESS);
	ASSERT_RETURN(ret == 0);

	/*
	 * children connections are able to talk to conn_db[0] since
	 * current POLICY_NAME TALK type is KDBUS_POLICY_ACCESS_WORLD,
	 * so expect EXIT_SUCCESS when sending from child. However,
	 * since the child's connection does not own any well-known
	 * name, The parent connection conn_db[0] should fail with
	 * -EPERM but since it is a privileged bus user the TALK is
	 *  allowed.
	 */
	ret = kdbus_fork_test_by_id(bus, conn_db,
				    EXIT_SUCCESS, EXIT_SUCCESS);
	ASSERT_EXIT(ret == 0);

	/*
	 * Connections that can talk are perhaps being destroyed now.
	 * Restrict the policy and purge cache entries where the
	 * conn_db[0] is the destination.
	 *
	 * Now only connections with uid == 0 are allowed to talk.
	 */
	ret = kdbus_set_policy_talk(policy_holder, POLICY_NAME,
				    geteuid(), KDBUS_POLICY_ACCESS_USER);
	ASSERT_RETURN(ret == 0);

	/*
	 * Testing connections (FORK+DROP) again:
	 * After setting the policy re-check connections
	 * we expect the children to fail with -EPERM
	 */
	ret = kdbus_fork_test(bus, POLICY_NAME, conn_db, -EPERM);
	ASSERT_RETURN(ret == 0);

	/*
	 * Now expect that both parent and child to fail.
	 *
	 * Child should fail with -EPERM since we just restricted
	 * the POLICY_NAME TALK to uid 0 and its uid is 65534.
	 *
	 * Since the parent's connection will timeout when receiving
	 * from the child, we never continue. FWIW just put -EPERM.
	 */
	ret = kdbus_fork_test_by_id(bus, conn_db, -EPERM, -EPERM);
	ASSERT_EXIT(ret == 0);

	/* Check if the name can be reached in a new userns */
	ret = kdbus_clone_userns_test(bus, POLICY_NAME, conn_db, -EPERM);
	ASSERT_RETURN(ret == 0);

	for (i = 0; i < MAX_CONN; i++)
		kdbus_conn_free(conn_db[i]);

	kdbus_conn_free(activator);
	kdbus_conn_free(policy_holder);

	free(conn_db);

	return ret;
}
