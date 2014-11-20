/* Test metadata in new namespaces */

#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <linux/sched.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static int __kdbus_clone_userns_test(const char *bus, struct kdbus_conn *conn)
{
	int efd = -1;
	pid_t pid;
	int ret;
	int status;
	unsigned int uid = 65534;
	int test_status = TEST_ERR;

	ret = drop_privileges(UNPRIV_UID, UNPRIV_GID);
	if (ret < 0)
		goto out;

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
		kdbus_printf("error prctl: %d (%m)\n", ret);
		goto out;
	}

	/* sync with parent */
	efd = eventfd(0, EFD_CLOEXEC);
	if (efd < 0) {
		ret = -errno;
		kdbus_printf("error eventfd: %d (%m)\n", ret);
		goto out;
	}

	pid = syscall(__NR_clone, SIGCHLD | CLONE_NEWUSER, NULL);
	if (pid < 0) {
		ret = -errno;
		kdbus_printf("error clone: %d (%m)\n", ret);

		/* Unprivileged can't create user namespace ? */
		if (ret == -EPERM) {
			kdbus_printf("-- CLONE_NEWUSER TEST Failed for "
				     "uid: %u\n -- Make sure that your kernel "
				     "do not allow CLONE_NEWUSER for "
				     "unprivileged users\n",
				uid);
			test_status = TEST_SKIP;
		}

		goto out;
	}

	if (pid == 0) {
		struct kdbus_conn *conn_src;
		eventfd_t event_status = 0;

		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0) {
			ret = -errno;
			kdbus_printf("error prctl: %d (%m)\n", ret);
			_exit(TEST_ERR);
		}

		ret = eventfd_read(efd, &event_status);
		if (ret < 0 || event_status != 1)
			_exit(TEST_ERR);

		/* ping connection from the new user namespace */
		conn_src = kdbus_hello(bus, 0, NULL, 0);
		ASSERT_EXIT(conn_src);

		ret = kdbus_add_match_empty(conn_src);
		ASSERT_EXIT(ret == 0);

		ret = kdbus_msg_send(conn_src, NULL, 0xabcd1234,
				     0, 0, 0, conn->id);
		ASSERT_EXIT(ret == 0);

		kdbus_conn_free(conn_src);
		_exit(TEST_OK);
	}

	ret = userns_map_uid_gid(pid, "0 65534 1", "0 65534 1");
	if (ret < 0) {
		/* send error to child */
		eventfd_write(efd, 2);
		kdbus_printf("error mapping uid/gid in new user namespace\n");
		goto out;
	}

	ret = eventfd_write(efd, 1);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error eventfd_write: %d (%m)\n", ret);
		goto out;
	}

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		ret = -errno;
		kdbus_printf("error waitpid: %d (%m)\n", ret);
		goto out;
	}

	if (WIFEXITED(status))
		test_status = WEXITSTATUS(status);

out:
	if (efd != -1)
		close(efd);

	return test_status;
}

/* Get only the first item */
static struct kdbus_item *kdbus_get_item(struct kdbus_msg *msg,
					 uint64_t type)
{
	struct kdbus_item *item;

	KDBUS_ITEM_FOREACH(item, msg, items)
		if (item->type == type)
			return item;

	return NULL;
}

static int kdbus_clone_userns_test(const char *bus, struct kdbus_conn *conn)
{
	int ret;
	pid_t pid;
	int status;
	struct kdbus_msg *msg;
	const struct kdbus_item *item;
	/* unpriv user will create its user_ns and change its uid/gid */
	const struct kdbus_creds unpriv_cached_creds = {
		.uid	= UNPRIV_UID,
		.gid	= UNPRIV_GID,
	};

	kdbus_printf("STARTING TEST 'metadata-ns' in a new user namespace.\n");

	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, -errno);

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		ASSERT_EXIT_VAL(ret == 0, -errno);

		ret = __kdbus_clone_userns_test(bus, conn);
		_exit(ret);
	}

	/* Receive in the original (root privileged) user namespace */
	ret = kdbus_msg_recv_poll(conn, 100, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	/* We do not get KDBUS_ITEM_CAPS */
	item = kdbus_get_item(msg, KDBUS_ITEM_CAPS);
	ASSERT_RETURN(item == NULL);

	item = kdbus_get_item(msg, KDBUS_ITEM_CREDS);
	ASSERT_RETURN(item);

	/*
	 * Compare received items, creds must be translated into
	 * the domain user namespace, so that used is unprivileged
	 */
	ASSERT_RETURN(item->creds.uid == unpriv_cached_creds.uid &&
		      item->creds.gid == unpriv_cached_creds.gid);

	kdbus_msg_free(msg);
	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN(ret >= 0);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return TEST_OK;
}

int kdbus_test_metadata_ns(struct kdbus_test_env *env)
{
	int ret;
	struct kdbus_conn *holder, *conn;
	struct kdbus_policy_access policy_access = {
		/* Allow world so we can inspect metadata in namespace */
		.type = KDBUS_POLICY_ACCESS_WORLD,
		.id = geteuid(),
		.access = KDBUS_POLICY_TALK,
	};

	/* we require user-namespaces */
	if (access("/proc/self/uid_map", F_OK) != 0)
		return TEST_SKIP;

	ret = test_is_capable(CAP_SETUID, CAP_SETGID, CAP_SYS_ADMIN, -1);
	ASSERT_RETURN(ret >= 0);

	/* no enough privileges, SKIP test */
	if (!ret)
		return TEST_SKIP;

	holder = kdbus_hello_registrar(env->buspath, "com.example.metadata",
				       &policy_access, 1,
				       KDBUS_HELLO_POLICY_HOLDER);
	ASSERT_RETURN(holder);

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

	ret = kdbus_add_match_empty(conn);
	ASSERT_RETURN(ret == 0);

	ret = kdbus_name_acquire(conn, "com.example.metadata", NULL);
	ASSERT_EXIT(ret >= 0);

	ret = kdbus_clone_userns_test(env->buspath, conn);
	ASSERT_RETURN(ret == 0);

	kdbus_conn_free(holder);
	kdbus_conn_free(conn);

	return TEST_OK;
}
