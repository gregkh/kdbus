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

#include "kdbus-util.h"
#include "kdbus-enum.h"

#define MAX_CONN	64
#define POLICY_NAME	"foo.test.policy-test"


/**
 * The purpose of these tests:
 * 1) Check KDBUS_POLICY_TALK
 * 2) Check the cache state: kdbus_policy_db->send_access_hash
 * Should be extended
 */

/**
 * Check a list of connections against conn_db[0]
 * conn_db[0] will be the policy holder and it will set
 * different policy accesses.
 */
static struct conn **conn_db;

void kdbus_free_conn(struct conn *conn)
{
	if (conn) {
		close(conn->fd);
		free(conn);
	}
}

/* Trigger kdbus_policy_set() */
static int kdbus_set_policy_talk(struct conn *conn,
				 const char *name,
				 uid_t id, unsigned int type)
{
	struct kdbus_policy_access access = {
		.type = type,
		.id = id,
		.access = KDBUS_POLICY_TALK,
	};

	return conn_update(conn, name, &access, 1, 0);
}

/* The policy access will be stored in a policy holder connection */
static int kdbus_register_activator(char *bus, const char *name,
				    struct conn **c)
{
	struct conn *activator;

	activator = kdbus_hello_activator(bus, name, NULL, 0);
	if (!activator)
		return -errno;

	*c = activator;

	return 0;
}

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
		return -errno;

	*conn = c;

	return 0;
}

static void *kdbus_recv_echo(void *ptr)
{
	int ret;
	int cnt = 3;
	struct pollfd fd;
	struct conn *conn = ptr;

	fd.fd = conn->fd;
	fd.events = POLLIN | POLLPRI | POLLHUP;
	fd.revents = 0;

	while (cnt) {
		cnt--;
		ret = poll(&fd, 1, 2000);
		if (ret == 0) {
			ret = -ETIMEDOUT;
			break;
		}

		if (ret > 0 && fd.revents & POLLIN) {
			printf("-- Connection id: %llu received new message:\n",
				(unsigned long long)conn->id);
			ret = msg_recv(conn);
		}

		if (ret >= 0 || ret != -EAGAIN)
			break;
	}

	return (void *)(long)ret;
}

/**
 * Just run a normal test, the 'conn_db' will be populated by
 * newly created connections. Caller should free all allocated
 * connections.
 *
 * return 0 on success, a non-zero on failure.
 */
static int kdbus_normal_test(const char *bus, const char *name,
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
		conn_db[i] = kdbus_hello(bus, 0);
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

static int kdbus_fork_test(const char *bus, const char *name,
			   struct conn **conn_db)
{
	int ret;
	int status;
	pid_t pid;
	int test_done = 0;

	if (geteuid() > 0) {
		fprintf(stderr, "error geteuid() != 0, %s() needs root\n",
			__func__);
		goto out;
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

		ret = kdbus_normal_test(bus, POLICY_NAME, conn_db);

		/*
		 * Here cached connections belong to child, they will
		 * be automatically destroyed.
		 */

		_exit(ret);
child_fail:
		_exit(EXIT_FAILURE);
	}

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		fprintf(stderr, "error waitpid: %d (%m)\n", ret);
		goto out;
	}

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret != EXIT_FAILURE) {
			if (ret != EXIT_SUCCESS)
				ret |= -1 << 8; /* get -errno */

			test_done = 1;	/* assume test reached */
		}
	}

out:
	/* test not reached, return -EIO and avoid EXIT_FAILURE */
	if (!test_done)
		ret = -EIO;

	return ret;
}

static int kdbus_check_policy(char *bus)
{
	int i;
	int ret;
	struct conn *activator = NULL;

	conn_db = calloc(MAX_CONN, sizeof(struct conn *));
	if (!conn_db)
		return -ENOMEM;

	memset(conn_db, 0, MAX_CONN * sizeof(struct conn *));

	ret = kdbus_register_policy_holder(bus, POLICY_NAME, &conn_db[0]);
	printf("-- TEST 1) register '%s' as policy holder ",
		POLICY_NAME);
	if (ret < 0) {
		printf("FAILED\n");
		goto out_free_connections;
	}

	printf("OK\n");

	/* Try to register the same name with an activator */
	ret = kdbus_register_activator(bus, POLICY_NAME, &activator);
	printf("-- TEST 2) register again '%s' as an activator ",
		POLICY_NAME);
	if (ret == 0) {
		printf("succeeded: TEST FAILED\n");
		fprintf(stderr, "--- error was able to register twice '%s'.\n",
			POLICY_NAME);
		ret = -1;
		goto out_free_connections;
	} else if (ret < 0) {
		/* -EEXIST means test succeeded */
		if (ret == -EEXIST) {
			ret = 0;
			printf("failed: TEST OK\n");
		} else {
			printf("FAILED\n");
			goto out_free_connections;
		}
	}

	ret = name_acquire(conn_db[0], POLICY_NAME, 0);
	printf("-- TEST 3) acquire '%s' name..... ", POLICY_NAME);
	if (ret < 0) {
		printf("FAILED\n");
		goto out_free_connections;
	}

	printf("OK\n");

	ret = kdbus_normal_test(bus, POLICY_NAME, conn_db);
	printf("-- TEST 4) testing connections (NORMAL TEST).... ");
	if (ret != 0) {
		printf("FAILED\n");
		goto out_free_connections;
	}

	printf("OK\n");

	name_list(conn_db[0], KDBUS_NAME_LIST_NAMES |
			      KDBUS_NAME_LIST_UNIQUE |
			      KDBUS_NAME_LIST_ACTIVATORS |
			      KDBUS_NAME_LIST_QUEUED);

	ret = kdbus_fork_test(bus, POLICY_NAME, conn_db);
	printf("-- TEST 5) testing connections (FORK+DROP)...... ");
	if (ret != 0) {
		printf("FAILED\n");
		goto out_free_connections;
	}

	printf("OK\n");

	/*
	 * Connections that can talk are perhaps being destroyed now.
	 * Restrict the policy and purge cache entries where the
	 * conn_db[0] is the destination.
	 */
	ret = kdbus_set_policy_talk(conn_db[0], POLICY_NAME,
				    geteuid(), KDBUS_POLICY_ACCESS_USER);
	printf("-- TEST 6) restricting policy '%s' TALK access ",
		POLICY_NAME);
	if (ret < 0) {
		printf("FAILED\n");
		goto out_free_connections;
	}

	printf("OK\n");

	/* After setting the policy re-check connections */
	ret = kdbus_fork_test(bus, POLICY_NAME, conn_db);
	printf("-- TEST 7) testing connections (FORK+DROP) again ");
	if (ret == 0) {
		printf("FAILED\n");
		fprintf(stderr, "--- error policy rules: send to all succeeded.\n");
		ret = -1;
	} else if (ret < 0) {
		/* -EPERM means tests succeeded */
		if (ret == -EPERM) {
			ret = 0;
			printf("OK\n");
		} else {
			printf("FAILED\n");
		}
	}

out_free_connections:
	kdbus_free_conn(activator);

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
	int fdc, ret, i;
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

	printf("RUNNING TEST 'policy db check' ");
	for (i = 0; i < 17; i++)
		printf(".");
	printf(" ");

	if (ret < 0) {
		printf("FAILED\n");
		return EXIT_FAILURE;
	}

	printf("OK\n");

	close(fdc);
	free(bus);

	return EXIT_SUCCESS;
}
