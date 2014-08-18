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

#include "kdbus-util.h"
#include "kdbus-enum.h"

/* Return: CHECK_OK, CHECK_ERR or CHECK_SKIP */
static int __kdbus_clone_userns_test(const char *bus, struct conn *conn)
{
	int efd = -1;
	pid_t pid;
	int ret;
	int status;
	unsigned int uid = 65534;
	int test_status = CHECK_ERR;

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
		fprintf(stderr, "error prctl: %d (%m)\n", ret);
		goto out;
	}

	/* sync with parent */
	efd = eventfd(0, EFD_CLOEXEC);
	if (efd < 0) {
		ret = -errno;
		fprintf(stderr, "error eventfd: %d (%m)\n", ret);
		goto out;
	}

	pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWUSER, NULL);
	if (pid < 0) {
		ret = -errno;
		fprintf(stderr, "error clone: %d (%m)\n", ret);

		/* Unprivileged can't create user namespace ? */
		if (ret == -EPERM) {
			printf("-- CLONE_NEWUSER TEST Failed for uid: %u\n"
				"-- Make sure that your kernel do not allow CLONE_NEWUSER for unprivileged users\n",
				uid);
			test_status = CHECK_SKIP;
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
			_exit(CHECK_ERR);
		}

		ret = eventfd_read(efd, &event_status);
		if (ret < 0 || event_status != 1)
			_exit(CHECK_ERR);

		/* ping connection from the new user namespace */
		conn_src = kdbus_hello(bus, 0, NULL, 0);
		if (!conn_src)
			_exit(CHECK_ERR);

		add_match_empty(conn_src->fd);
		ret = msg_send(conn_src, NULL, 0xabcd1234,
			       0, 0, 0, conn->id);
		if (ret < 0)
			_exit(CHECK_ERR);

		close(conn_src->fd);
		free(conn_src);

		_exit(CHECK_OK);
	}

	ret = userns_map_uid_gid(pid, "0 65534 1", "0 65534 1");
	if (ret < 0) {
		/* send error to child */
		eventfd_write(efd, 2);
		fprintf(stderr, "error mapping uid/gid in new user namespace\n");
		goto out;
	}

	ret = eventfd_write(efd, 1);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error eventfd_write: %d (%m)\n", ret);
		goto out;
	}

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error waitpid: %d (%m)\n", ret);
		goto out;
	}

	if (WIFEXITED(status))
		test_status = WEXITSTATUS(status);

out:
	if (efd != -1)
		close(efd);

	return test_status;
}

static int kdbus_clone_userns_test(const char *bus, struct conn *conn)
{
	int ret;
	pid_t pid;
	int status;
	int test_status = CHECK_ERR;

	setbuf(stdout, NULL);
	printf("STARTING TEST 'chat' in a new user namespace........\n");
	if (geteuid() > 0) {
		fprintf(stderr, "geteuid() != 0, %s() needs root\n",
			__func__);
		test_status = CHECK_SKIP;
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
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "error prctl: %d (%m)\n", ret);
			_exit(CHECK_ERR);
		}

		ret = __kdbus_clone_userns_test(bus, conn);
		_exit(ret);
	}

	/* Receive in the original (root privileged) user namespace */
	ret = conn_recv(conn);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error recv: %d (%m)\n", ret);
		goto out;
	}

	ret = waitpid(pid, &status, 0);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "error waitpid: %d (%m)\n", ret);
		goto out;
	}

	if (WIFEXITED(status))
		test_status = WEXITSTATUS(status);

out:
	printf("RUNNING TEST 'chat' in a new user namespace........ ");
	switch (test_status) {
	case CHECK_OK:
		printf("OK");
		break;
	case CHECK_SKIP:
		printf("SKIPPED");
		break;
	case CHECK_ERR:
	default:
		printf("ERROR");
		break;
	}

	printf("\n");

	return 0;
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
	struct conn *conn_a;

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

	/* A world readable bus to test user namespace metadata... */
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

	conn_a = kdbus_hello(bus, 0, NULL, 0);
	if (!conn_a)
		return EXIT_FAILURE;

	add_match_empty(conn_a->fd);

	kdbus_clone_userns_test(bus, conn_a);

	printf("-- closing bus connections\n");
	close(conn_a->fd);
	free(conn_a);

	printf("-- closing bus master\n");
	close(fdc);
	free(bus);

	return EXIT_SUCCESS;
}
