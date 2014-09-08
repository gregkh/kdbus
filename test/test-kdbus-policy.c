/*
 * Copyright (C) 2014 Djalal Harouni
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
#include <poll.h>
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
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

#define MAX_CONN	64
#define POLICY_NAME	"foo.test.policy-test"

static int ok_cnt;
static int skip_cnt;
static int fail_cnt;

static void print_test_status(int test_status)
{
	switch (test_status) {
	case CHECK_OK:
		printf("OK");
		ok_cnt++;
		break;
	case CHECK_SKIP:
		printf("SKIPPED");
		skip_cnt++;
		break;
	case CHECK_ERR:
	default:
		printf("ERROR");
		fail_cnt++;
		break;
	}

	printf("\n");
}

/**
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
static struct conn **conn_db;

void kdbus_free_conn(struct conn *conn)
{
	if (conn) {
		close(conn->fd);
		free(conn);
	}
}

static void *kdbus_recv_echo(void *ptr)
{
	int ret;
	struct conn *conn = ptr;

	ret = conn_recv(conn);

	return (void *)(long)ret;
}

/* Trigger kdbus_policy_set() */
static int kdbus_set_policy_talk(struct conn *conn,
				 const char *name,
				 uid_t id, unsigned int type)
{
	int ret;
	struct kdbus_policy_access access = {
		.type = type,
		.id = id,
		.access = KDBUS_POLICY_TALK,
	};

	ret = conn_update_policy(conn, name, &access, 1);
	if (ret < 0)
		return CHECK_ERR;

	return CHECK_OK;
}

/* return CHECK_OK or CHECK_ERR on failure */
static int kdbus_register_same_activator(char *bus, const char *name,
					 struct conn **c)
{
	int ret;
	struct conn *activator;

	activator = kdbus_hello_activator(bus, name, NULL, 0);
	if (activator) {
		*c = activator;
		fprintf(stderr, "--- error was able to register name twice '%s'.\n",
			name);
		return CHECK_ERR;
	}

	ret = -errno;
	/* -EEXIST means test succeeded */
	if (ret == -EEXIST)
		return CHECK_OK;

	return CHECK_ERR;
}

/* return CHECK_OK or CHECK_ERR on failure */
static int kdbus_register_policy_holder(char *bus, const char *name,
					struct conn **conn)
{
	struct conn *c;
	struct kdbus_policy_access access[2];

	access[0].type = KDBUS_POLICY_ACCESS_USER;
	access[0].access = KDBUS_POLICY_OWN;
	access[0].id = geteuid();

	access[1].type = KDBUS_POLICY_ACCESS_WORLD;
	access[1].access = KDBUS_POLICY_TALK;
	access[1].id = geteuid();

	c = kdbus_hello_registrar(bus, name, access, 2,
				  KDBUS_HELLO_POLICY_HOLDER);
	if (!c)
		return CHECK_ERR;

	*conn = c;

	return CHECK_OK;
}

/* return CHECK_OK or CHECK_ERR on failure */
static int kdbus_receiver_acquire_name(char *bus, const char *name,
					struct conn **conn)
{
	int ret;
	struct conn *c;

	c = kdbus_hello(bus, 0, NULL, 0);
	if (!c)
		return CHECK_ERR;

	add_match_empty(c->fd);

	ret = name_acquire(c, name, 0);
	if (ret < 0)
		return CHECK_ERR;

	*conn = c;

	return CHECK_OK;
}

/**
 * Return the exit code of the child process and set the test_done
 * variable if the test was performed:
 * In case of WIFEXITED():
 *   1) If exit code != EXIT_FAILURE assume test reached and set the
 *      'test_done' variable if provided to 1.
 *   2) If exit code != EXIT_FAILURE and exit code != EXIT_SUCCESS:
 *      Convert the exit code to a proper -errno and return it.
 * In all other cases:
 *   set the exit code to EXIT_FAILURE and return it.
 */
static int kdbus_test_waitpid(pid_t pid, int *test_done)
{
	int ret;
	int status;

	int test_performed = 0;

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error waitpid: %d (%m)\n", ret);
		return ret;
	}

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret != EXIT_FAILURE) {
			if (ret != EXIT_SUCCESS)
				ret |= -1 << 8; /* get -errno */

			/* test reached */
			test_performed = 1;
		}
	} else {
		ret = EXIT_FAILURE;
	}

	if (test_done)
		*test_done = test_performed;

	return ret;
}

/**
 * Create new threads for receiving from multiple senders,
 * The 'conn_db' will be populated by newly created connections.
 * Caller should free all allocated connections.
 *
 * return 0 on success, negative errno on failure.
 */
static int kdbus_recv_in_threads(const char *bus, const char *name,
				 struct conn **conn_db)
{
	int ret;
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
			fprintf(stderr, "error pthread_create: %d err %d (%m)\n",
				ret, errno);
				break;
		}

		/* just free before re-using */
		kdbus_free_conn(conn_db[i]);
		conn_db[i] = NULL;

		/* We need to create connections here */
		conn_db[i] = kdbus_hello(bus, 0, NULL, 0);
		if (!conn_db[i]) {
			ret = -errno;
			break;
		}

		add_match_empty(conn_db[i]->fd);

		ret = msg_send(conn_db[i], name, cookie++,
				0, 0, 0, dst_id);
		if (ret < 0)
			break;
	}

	for (tid = 0; tid < thread_nr; tid++) {
		int thread_ret = 0;
		if (thread_id[tid]) {
			pthread_join(thread_id[tid], (void *)&thread_ret);
			if (thread_ret < 0 && ret == 0)
				ret = thread_ret;
		}
	}

	return ret;
}

/* Return: CHECK_OK or CHECK_ERR on failure */
static int kdbus_normal_test(const char *bus, const char *name,
			   struct conn **conn_db)
{
	int ret;

	ret = kdbus_recv_in_threads(bus, name, conn_db);
	if (ret < 0)
		return CHECK_ERR;

	return CHECK_OK;
}

/*
 * Return: CHECK_OK, CHECK_ERR or CHECK_SKIP
 * we return CHECK_OK only if the childs return with the expected
 * 'exit_code' that is specified as an argument.
 */
static int kdbus_fork_test(const char *bus, const char *name,
			   struct conn **conn_db, int exit_code)
{
	pid_t pid;
	int ret = 0;
	int test_done = 0;
	int test_status = CHECK_ERR;

	setbuf(stdout, NULL);
	printf("STARTING the (FORK+DROP) test...............\n");
	if (geteuid() > 0) {
		fprintf(stderr, "error geteuid() != 0, %s() needs root\n",
			__func__);
		return CHECK_SKIP;
	}

	pid = fork();
	if (pid < 0) {
		ret = -errno;
		fprintf(stderr, "error fork(): %d (%m)\n", ret);
		goto out;
	}

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0)
			goto child_fail;

		ret = drop_privileges(65534, 65534);
		if (ret < 0)
			goto child_fail;

		ret = kdbus_recv_in_threads(bus, name, conn_db);

		/*
		 * Here cached connections belong to child, they will
		 * be automatically destroyed.
		 */

		_exit(ret);
child_fail:
		_exit(EXIT_FAILURE);
	}

	ret = kdbus_test_waitpid(pid, &test_done);

out:
	/* test reached */
	if (test_done) {
		if (ret == exit_code)
			test_status = CHECK_OK;
		else
			fprintf(stderr,
				"error TEST exit code: %d  was expecting code: %d\n",
				ret, exit_code);
	}

	return test_status;
}

/* Return EXIT_SUCCESS, EXIT_FAILURE or negative errno */
static int __kdbus_clone_userns_test(const char *bus,
				     const char *name,
				     struct conn **conn_db)
{
	int efd;
	pid_t pid;
	int ret = 0;
	unsigned int uid = 65534;

	ret = drop_privileges(uid, uid);
	if (ret < 0)
		return ret;

	/**
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
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error prctl: %d (%m)\n", ret);
		return ret;
	}

	/* sync parent/child */
	efd = eventfd(0, EFD_CLOEXEC);
	if (efd < 0) {
		ret = -errno;
		fprintf(stderr, "error eventfd: %d (%m)\n", ret);
		return ret;
	}

	pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWUSER, NULL);
	if (pid < 0) {
		ret = -errno;
		fprintf(stderr, "error clone: %d (%m)\n", ret);
		/*
		 * Normal user not allowed to create userns,
		 * so nothing to worry about ?
		 */
		if (ret == -EPERM) {
			printf("-- CLONE_NEWUSER TEST Failed for uid: %u\n"
				"-- Make sure that your kernel do not allow CLONE_NEWUSER for unprivileged users\n"
				"-- Upstream Commit: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=5eaf563e53294d6696e651466697eb9d491f3946\n",
				uid);
			ret = 0;
		}

		goto out;
	}

	if (pid == 0) {
		struct conn *conn_src;
		eventfd_t event_status = 0;

		setbuf(stdout, NULL);
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "error prctl: %d (%m)\n", ret);
			goto child_fail;
		}

		ret = eventfd_read(efd, &event_status);
		if (ret < 0 || event_status != 1)
			/* event_stats == 1 to continue */
			goto child_fail;

		/* ping connection from the new user namespace */
		conn_src = kdbus_hello(bus, 0, NULL, 0);
		if (!conn_src)
			goto child_fail;

		add_match_empty(conn_src->fd);
		ret = msg_send(conn_src, name, 0xabcd1234,
			       0, 0, 0, KDBUS_DST_ID_NAME);

		close(conn_src->fd);
		free(conn_src);
		_exit(ret);

child_fail:
		_exit(EXIT_FAILURE);
	}

	ret = userns_map_uid_gid(pid, "0 65534 1", "0 65534 1");
	if (ret < 0) {
		/* send error to child */
		eventfd_write(efd, 2);
		fprintf(stderr, "error mapping uid/gid in new user namespace\n");
		goto out;
	}

	/* Tell child we are ready */
	ret = eventfd_write(efd, 1);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error eventfd_write: %d (%m)\n", ret);
		goto out;
	}

	ret = kdbus_test_waitpid(pid, NULL);

out:
	close(efd);

	return ret;
}

static int kdbus_clone_userns_test(const char *bus,
				   const char *name,
				   struct conn **conn_db,
				   int exit_code)
{
	pid_t pid;
	int ret = 0;
	int test_done = 0;
	int test_status = CHECK_ERR;

	setbuf(stdout, NULL);
	printf("STARTING TEST connections in a new user namespace..\n");
	if (geteuid() > 0) {
		fprintf(stderr, "error geteuid() != 0, %s() needs root\n",
			__func__);
		return CHECK_SKIP;
	}

	pid = fork();
	if (pid < 0) {
		ret = -errno;
		fprintf(stderr, "error fork(): %d (%m)\n", ret);
		goto out;
	}

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0)
			goto child_fail;

		ret = __kdbus_clone_userns_test(bus, name, conn_db);
		_exit(ret);
child_fail:
		_exit(EXIT_FAILURE);
	}

	/* Receive in the original (root privileged) user namespace */
	ret = conn_recv(conn_db[0]);
	if (!ret) {
		fprintf(stderr,
			"--- error received packet from unprivileged user namespace\n");
		goto out;
	}

	ret = kdbus_test_waitpid(pid, &test_done);

out:
	/* test reached */
	if (test_done) {
		/* Set to CHECK_OK if we did get the right exit_code */
		if (ret == exit_code)
			test_status = CHECK_OK;
		else
			fprintf(stderr,
				"error TEST exit code: %d  was expecting code: %d\n",
				ret, exit_code);
	}

	return test_status;
}

/* Return CHECK_OK, CHECK_ERR or CHECK_SKIP */
static int kdbus_check_policy(char *bus)
{
	int i;
	int ret;
	struct conn *activator = NULL;
	struct conn *policy_holder = NULL;

	conn_db = calloc(MAX_CONN, sizeof(struct conn *));
	if (!conn_db)
		return -ENOMEM;

	memset(conn_db, 0, MAX_CONN * sizeof(struct conn *));

	ret = kdbus_register_policy_holder(bus, POLICY_NAME,
					   &policy_holder);
	printf("-- TEST 1) register a policy holder for '%s' ",
		POLICY_NAME);
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	/* Try to register the same name with an activator */
	ret = kdbus_register_same_activator(bus, POLICY_NAME,
					    &activator);
	printf("-- TEST 2) register again '%s' as an activator ",
		POLICY_NAME);
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	ret = kdbus_receiver_acquire_name(bus, POLICY_NAME, &conn_db[0]);
	printf("-- TEST 3) acquire '%s' name..... ", POLICY_NAME);
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	ret = kdbus_normal_test(bus, POLICY_NAME, conn_db);
	printf("-- TEST 4) testing connections (NORMAL TEST).... ");
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	name_list(conn_db[0], KDBUS_NAME_LIST_NAMES |
			      KDBUS_NAME_LIST_UNIQUE |
			      KDBUS_NAME_LIST_ACTIVATORS |
			      KDBUS_NAME_LIST_QUEUED);

	ret = kdbus_fork_test(bus, POLICY_NAME, conn_db, EXIT_SUCCESS);
	printf("-- TEST 5) testing connections (FORK+DROP)...... ");
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	/*
	 * Connections that can talk are perhaps being destroyed now.
	 * Restrict the policy and purge cache entries where the
	 * conn_db[0] is the destination.
	 *
	 * Now only connections with uid == 0 are allowed to talk.
	 */
	ret = kdbus_set_policy_talk(policy_holder, POLICY_NAME,
				    geteuid(), KDBUS_POLICY_ACCESS_USER);
	printf("-- TEST 6) restricting '%s' policy TALK access ",
		POLICY_NAME);
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	printf("-- TEST 7) testing connections (FORK+DROP) again\n");
	/*
	 * After setting the policy re-check connections
	 * we expect the childs to fail with -EPERM
	 */
	ret = kdbus_fork_test(bus, POLICY_NAME, conn_db, -EPERM);
	printf("-- TEST 7) testing connections (FORK+DROP) again ");
	print_test_status(ret);
	if (ret == CHECK_ERR)
		goto out_free_connections;

	printf("-- TEST 8) testing connections in a new user namespace\n");
	/* Check if the name can be reached in a new userns */
	ret = kdbus_clone_userns_test(bus, POLICY_NAME,
				      conn_db, -EPERM);
	printf("-- TEST 8) testing connections in a new user namespace ");
	print_test_status(ret);

out_free_connections:
	kdbus_free_conn(activator);
	kdbus_free_conn(policy_holder);

	for (i = 0; i < MAX_CONN; i++)
		kdbus_free_conn(conn_db[i]);

	free(conn_db);

	return ret;
}

int main(int argc, char *argv[])
{
	struct {
		struct kdbus_cmd_make head;

		/* bloom size item */
		struct {
			uint64_t size;
			uint64_t type;
			struct kdbus_bloom_parameter bloom;
		} bs;

		/* name item */
		uint64_t n_size;
		uint64_t n_type;
		char name[64];
	} bus_make;
	int fdc, ret;
	char *bus;

	printf("-- opening /dev/" KBUILD_MODNAME "/control\n");
	fdc = open("/dev/" KBUILD_MODNAME "/control", O_RDWR|O_CLOEXEC);
	if (fdc < 0) {
		fprintf(stderr, "--- error %d (%m)\n", fdc);
		return EXIT_FAILURE;
	}

	memset(&bus_make, 0, sizeof(bus_make));
	bus_make.bs.size = sizeof(bus_make.bs);
	bus_make.bs.type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bs.bloom.size = 64;
	bus_make.bs.bloom.n_hash = 1;

	snprintf(bus_make.name, sizeof(bus_make.name), "%u-testbus", getuid());
	bus_make.n_type = KDBUS_ITEM_MAKE_NAME;
	bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;

	/* A world readable bus to test different uid/gid... */
	bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;
	bus_make.head.size = sizeof(struct kdbus_cmd_make) +
			     sizeof(bus_make.bs) +
			     bus_make.n_size;

	printf("-- creating bus '%s'\n", bus_make.name);
	ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &bus_make);
	if (ret) {
		fprintf(stderr, "--- error %d (%m)\n", ret);
		return EXIT_FAILURE;
	}

	if (asprintf(&bus, "/dev/" KBUILD_MODNAME "/%s/bus", bus_make.name) < 0)
		return EXIT_FAILURE;

	ret = kdbus_check_policy(bus);

	printf("\nSUMMARY: %d tests passed, %d skipped%s, %d failed\n",
		ok_cnt, skip_cnt,
		skip_cnt ? " (need privileges)" : "", fail_cnt);

	if (skip_cnt > 0)
		printf("For security reasons make sure to re-run skipped tests.\n");

	printf("RUNNING TEST 'policy db check'................ ");
	if (fail_cnt > 0) {
		printf("Failed\n");
		return EXIT_FAILURE;
	}

	printf("OK\n");

	close(fdc);
	free(bus);

	return EXIT_SUCCESS;
}
