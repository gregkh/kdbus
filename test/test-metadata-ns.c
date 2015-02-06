/*
 * Test metadata in new namespaces. Even if our tests can run
 * in a namespaced setup, this test is necessary so we can inspect
 * metadata on the same kdbusfs but between multiple namespaces
 */

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
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <linux/sched.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

static const struct kdbus_creds privileged_creds = {};

static const struct kdbus_creds unmapped_creds = {
	.uid	= UNPRIV_UID,
	.euid	= UNPRIV_UID,
	.suid	= UNPRIV_UID,
	.fsuid	= UNPRIV_UID,
	.gid	= UNPRIV_GID,
	.egid	= UNPRIV_GID,
	.sgid	= UNPRIV_GID,
	.fsgid	= UNPRIV_GID,
};

static const struct kdbus_pids unmapped_pids = {};

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

static int kdbus_match_kdbus_creds(struct kdbus_msg *msg,
				   const struct kdbus_creds *expected_creds)
{
	struct kdbus_item *item;

	item = kdbus_get_item(msg, KDBUS_ITEM_CREDS);
	ASSERT_RETURN(item);

	ASSERT_RETURN(memcmp(&item->creds, expected_creds,
			     sizeof(struct kdbus_creds)) == 0);

	return 0;
}

static int kdbus_match_kdbus_pids(struct kdbus_msg *msg,
				  const struct kdbus_pids *expected_pids)
{
	struct kdbus_item *item;

	item = kdbus_get_item(msg, KDBUS_ITEM_PIDS);
	ASSERT_RETURN(item);

	ASSERT_RETURN(memcmp(&item->pids, expected_pids,
			     sizeof(struct kdbus_pids)) == 0);

	return 0;
}

static int __kdbus_clone_userns_test(const char *bus,
				     struct kdbus_conn *conn,
				     uint64_t grandpa_pid,
				     int signal_fd)
{
	int clone_ret;
	int ret;
	struct kdbus_msg *msg = NULL;
	const struct kdbus_item *item;
	uint64_t cookie = time(NULL) ^ 0xdeadbeef;
	struct kdbus_conn *unpriv_conn = NULL;
	struct kdbus_pids parent_pids = {
		.pid = getppid(),
		.tid = getppid(),
		.ppid = grandpa_pid,
	};

	ret = drop_privileges(UNPRIV_UID, UNPRIV_GID);
	ASSERT_EXIT(ret == 0);

	unpriv_conn = kdbus_hello(bus, 0, NULL, 0);
	ASSERT_EXIT(unpriv_conn);

	ret = kdbus_add_match_empty(unpriv_conn);
	ASSERT_EXIT(ret == 0);

	/*
	 * ping privileged connection from this new unprivileged
	 * one
	 */

	ret = kdbus_msg_send(unpriv_conn, NULL, cookie, 0, 0,
			     0, conn->id);
	ASSERT_EXIT(ret == 0);

	/*
	 * Since we just dropped privileges, the dumpable flag
	 * was just cleared which makes the /proc/$clone_child/uid_map
	 * to be owned by root, hence any userns uid mapping will fail
	 * with -EPERM since the mapping will be done by uid 65534.
	 *
	 * To avoid this set the dumpable flag again which makes
	 * procfs update the /proc/$clone_child/ inodes owner to 65534.
	 *
	 * Using this we will be able write to /proc/$clone_child/uid_map
	 * as uid 65534 and map the uid 65534 to 0 inside the user namespace.
	 */
	ret = prctl(PR_SET_DUMPABLE, SUID_DUMP_USER);
	ASSERT_EXIT(ret == 0);

	/* Make child privileged in its new userns and run tests */

	ret = RUN_CLONE_CHILD(&clone_ret,
			      SIGCHLD | CLONE_NEWUSER | CLONE_NEWPID,
	({ 0;  /* Clone setup, nothing */ }),
	({
		eventfd_t event_status = 0;
		struct kdbus_conn *userns_conn;

		/* ping connection from the new user namespace */
		userns_conn = kdbus_hello(bus, 0, NULL, 0);
		ASSERT_EXIT(userns_conn);

		ret = kdbus_add_match_empty(userns_conn);
		ASSERT_EXIT(ret == 0);

		cookie++;
		ret = kdbus_msg_send(userns_conn, NULL, cookie,
				     0, 0, 0, conn->id);
		ASSERT_EXIT(ret == 0);

		/* Parent did send */
		ret = eventfd_read(signal_fd, &event_status);
		ASSERT_RETURN(ret >= 0 && event_status == 1);

		/*
		 * Receive from privileged connection
		 */
		kdbus_printf("Privileged → unprivileged/privileged "
			     "in its userns "
			     "(different userns and pidns):\n");
		ret = kdbus_msg_recv_poll(userns_conn, 300, &msg, NULL);
		ASSERT_EXIT(ret == 0);
		ASSERT_EXIT(msg->dst_id == userns_conn->id);

		/* Different namespaces no CAPS */
		item = kdbus_get_item(msg, KDBUS_ITEM_CAPS);
		ASSERT_EXIT(item == NULL);

		/* uid/gid not mapped, so we have unpriv cached creds */
		ret = kdbus_match_kdbus_creds(msg, &unmapped_creds);
		ASSERT_EXIT(ret == 0);

		/*
		 * Diffent pid namepsaces. This is the child pidns
		 * so it should not see its parent kdbus_pids
		 */
		ret = kdbus_match_kdbus_pids(msg, &unmapped_pids);
		ASSERT_EXIT(ret == 0);

		kdbus_msg_free(msg);


		/*
		 * Receive broadcast from privileged connection
		 */
		kdbus_printf("Privileged → unprivileged/privileged "
			     "in its userns "
			     "(different userns and pidns):\n");
		ret = kdbus_msg_recv_poll(userns_conn, 300, &msg, NULL);
		ASSERT_EXIT(ret == 0);
		ASSERT_EXIT(msg->dst_id == KDBUS_DST_ID_BROADCAST);

		/* Different namespaces no CAPS */
		item = kdbus_get_item(msg, KDBUS_ITEM_CAPS);
		ASSERT_EXIT(item == NULL);

		/* uid/gid not mapped, so we have unpriv cached creds */
		ret = kdbus_match_kdbus_creds(msg, &unmapped_creds);
		ASSERT_EXIT(ret == 0);

		/*
		 * Diffent pid namepsaces. This is the child pidns
		 * so it should not see its parent kdbus_pids
		 */
		ret = kdbus_match_kdbus_pids(msg, &unmapped_pids);
		ASSERT_EXIT(ret == 0);

		kdbus_msg_free(msg);

		kdbus_conn_free(userns_conn);
	}),
	({
		/* Parent setup map child uid/gid */
		ret = userns_map_uid_gid(pid, "0 65534 1", "0 65534 1");
		ASSERT_EXIT(ret == 0);
	}),
	({ 0; }));
	/* Unprivileged was not able to create user namespace */
	if (clone_ret == -EPERM) {
		kdbus_printf("-- CLONE_NEWUSER TEST Failed for "
			     "uid: %u\n -- Make sure that your kernel "
			     "do not allow CLONE_NEWUSER for "
			     "unprivileged users\n", UNPRIV_UID);
		ret = 0;
		goto out;
	}

	ASSERT_EXIT(ret == 0);


	/*
	 * Receive from privileged connection
	 */
	kdbus_printf("\nPrivileged → unprivileged (same namespaces):\n");
	ret = kdbus_msg_recv_poll(unpriv_conn, 300, &msg, NULL);

	ASSERT_EXIT(ret == 0);
	ASSERT_EXIT(msg->dst_id == unpriv_conn->id);

	/* will get the privileged creds */
	ret = kdbus_match_kdbus_creds(msg, &privileged_creds);
	ASSERT_EXIT(ret == 0);

	/* Same pidns so will get the kdbus_pids */
	ret = kdbus_match_kdbus_pids(msg, &parent_pids);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);


	/*
	 * Receive broadcast from privileged connection
	 */
	kdbus_printf("\nPrivileged → unprivileged (same namespaces):\n");
	ret = kdbus_msg_recv_poll(unpriv_conn, 300, &msg, NULL);

	ASSERT_EXIT(ret == 0);
	ASSERT_EXIT(msg->dst_id == KDBUS_DST_ID_BROADCAST);

	/* will get the privileged creds */
	ret = kdbus_match_kdbus_creds(msg, &privileged_creds);
	ASSERT_EXIT(ret == 0);

	ret = kdbus_match_kdbus_pids(msg, &parent_pids);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);

out:
	kdbus_conn_free(unpriv_conn);

	return ret;
}

static int kdbus_clone_userns_test(const char *bus,
				   struct kdbus_conn *conn)
{
	int ret;
	int status;
	int efd = -1;
	pid_t pid, ppid;
	uint64_t unpriv_conn_id = 0;
	uint64_t userns_conn_id = 0;
	struct kdbus_msg *msg;
	const struct kdbus_item *item;
	struct kdbus_pids expected_pids;
	struct kdbus_conn *monitor = NULL;

	kdbus_printf("STARTING TEST 'metadata-ns'.\n");

	monitor = kdbus_hello(bus, KDBUS_HELLO_MONITOR, NULL, 0);
	ASSERT_EXIT(monitor);

	/*
	 * parent will signal to child that is in its
	 * userns to read its queue
	 */
	efd = eventfd(0, EFD_CLOEXEC);
	ASSERT_RETURN_VAL(efd >= 0, efd);

	ppid = getppid();

	pid = fork();
	ASSERT_RETURN_VAL(pid >= 0, -errno);

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		ASSERT_EXIT_VAL(ret == 0, -errno);

		ret = __kdbus_clone_userns_test(bus, conn, ppid, efd);
		_exit(ret);
	}


	/* Phase 1) privileged receives from unprivileged */

	/*
	 * Receive from the unprivileged child
	 */
	kdbus_printf("\nUnprivileged → privileged (same namespaces):\n");
	ret = kdbus_msg_recv_poll(conn, 300, &msg, NULL);
	ASSERT_RETURN(ret == 0);

	unpriv_conn_id = msg->src_id;

	/* Unprivileged user */
	ret = kdbus_match_kdbus_creds(msg, &unmapped_creds);
	ASSERT_RETURN(ret == 0);

	/* Set the expected creds_pids */
	expected_pids = (struct kdbus_pids) {
		.pid = pid,
		.tid = pid,
		.ppid = getpid(),
	};
	ret = kdbus_match_kdbus_pids(msg, &expected_pids);
	ASSERT_RETURN(ret == 0);

	kdbus_msg_free(msg);


	/*
	 * Receive from the unprivileged that is in his own
	 * userns and pidns
	 */

	kdbus_printf("\nUnprivileged/privileged in its userns → privileged "
		     "(different userns and pidns)\n");
	ret = kdbus_msg_recv_poll(conn, 300, &msg, NULL);
	if (ret == -ETIMEDOUT)
		/* perhaps unprivileged userns is not allowed */
		goto wait;

	ASSERT_RETURN(ret == 0);

	userns_conn_id = msg->src_id;

	/* We do not share the userns, os no KDBUS_ITEM_CAPS */
	item = kdbus_get_item(msg, KDBUS_ITEM_CAPS);
	ASSERT_RETURN(item == NULL);

	/*
	 * Compare received items, creds must be translated into
	 * the receiver user namespace, so the user is unprivileged
	 */
	ret = kdbus_match_kdbus_creds(msg, &unmapped_creds);
	ASSERT_RETURN(ret == 0);

	/*
	 * We should have the kdbus_pids since we are the parent
	 * pidns
	 */
	item = kdbus_get_item(msg, KDBUS_ITEM_PIDS);
	ASSERT_RETURN(item);

	ASSERT_RETURN(memcmp(&item->pids, &unmapped_pids,
			     sizeof(struct kdbus_pids)) != 0);

	/*
	 * Parent pid of the unprivileged/privileged in its userns
	 * is the unprivileged child pid that was forked here.
	 */
	ASSERT_RETURN((uint64_t)pid == item->pids.ppid);

	kdbus_msg_free(msg);


	/* Phase 2) Privileged connection sends now 3 packets */

	/*
	 * Sending to unprivileged connections a unicast
	 */
	ret = kdbus_msg_send(conn, NULL, 0xdeadbeef, 0, 0,
			     0, unpriv_conn_id);
	ASSERT_RETURN(ret == 0);

	/* signal to child that is in its userns */
	ret = eventfd_write(efd, 1);
	ASSERT_EXIT(ret == 0);

	/*
	 * Sending to unprivileged/privilged in its userns
	 * connections a unicast
	 */
	ret = kdbus_msg_send(conn, NULL, 0xdeadbeef, 0, 0,
			     0, userns_conn_id);
	ASSERT_RETURN(ret == 0);

	/*
	 * Sending to unprivileged connections a broadcast
	 */
	ret = kdbus_msg_send(conn, NULL, 0xdeadbeef, 0, 0,
			     0, KDBUS_DST_ID_BROADCAST);
	ASSERT_RETURN(ret == 0);


wait:
	ret = waitpid(pid, &status, 0);
	ASSERT_RETURN(ret >= 0);

	ASSERT_RETURN(WIFEXITED(status))
	ASSERT_RETURN(!WEXITSTATUS(status));

	/* Dump monitor queue */
	kdbus_printf("\n\nMonitor queue:\n");
	for (;;) {
		ret = kdbus_msg_recv_poll(monitor, 100, &msg, NULL);
		if (ret < 0)
			break;

		if (msg->payload_type == KDBUS_PAYLOAD_DBUS) {
			/*
			 * Parent pidns should see all the
			 * pids
			 */
			item = kdbus_get_item(msg, KDBUS_ITEM_PIDS);
			ASSERT_RETURN(item);

			ASSERT_RETURN(item->pids.pid != 0 &&
				      item->pids.tid != 0 &&
				      item->pids.ppid != 0);
		}

		kdbus_msg_free(msg);
	}

	kdbus_conn_free(monitor);
	close(efd);

	return 0;
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

	/*
	 * We require user-namespaces and all uids/gids
	 * should be mapped (we can just require the necessary ones)
	 */
	if (!config_user_ns_is_enabled() ||
	    !all_uids_gids_are_mapped())
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
