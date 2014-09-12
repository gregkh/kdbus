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
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <stdbool.h>

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

	ret = drop_privileges(uid, uid);
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
			kdbus_printf("-- CLONE_NEWUSER TEST Failed for uid: %u\n"
				"-- Make sure that your kernel do not allow "
				"CLONE_NEWUSER for unprivileged users\n",
				uid);
			test_status = TEST_SKIP;
		}

		goto out;
	}

	if (pid == 0) {
		struct kdbus_conn *conn_src;
		eventfd_t event_status = 0;

		setbuf(stdout, NULL);
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

static int kdbus_clone_userns_test(const char *bus, struct kdbus_conn *conn)
{
	int ret;
	pid_t pid;
	int status;

	kdbus_printf("STARTING TEST 'chat' in a new user namespace.\n");

	setbuf(stdout, NULL);
	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, -errno);

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		ASSERT_EXIT_VAL(ret == 0, -errno);

		ret = __kdbus_clone_userns_test(bus, conn);
		_exit(ret);
	}

	/* Receive in the original (root privileged) user namespace */
	ret = kdbus_msg_recv_poll(conn, NULL, 1000);
	ASSERT_RETURN(ret == 0);

	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN(ret >= 0);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return TEST_OK;
}

int kdbus_test_metadata_ns(struct kdbus_test_env *env)
{
	int ret;

	/* this test needs root privileges */
	if (geteuid() > 0)
		return TEST_SKIP;

	ret = kdbus_add_match_empty(env->conn);
	ASSERT_RETURN(ret == 0);

	return kdbus_clone_userns_test(env->buspath, env->conn);
}
