#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "kdbus-test.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"

#define UNPRIV_UID 65534
#define UNPRIV_GID 65534

#define RUN_UNPRIVILEGED(_child_, _parent_) ({				\
		pid_t pid, rpid;					\
		int ret;						\
									\
		pid = fork();						\
		if (pid == 0) {						\
			ret = drop_privileges(UNPRIV_UID, UNPRIV_GID);	\
			if (ret < 0)					\
				_exit(ret);				\
									\
			_child_;					\
			_exit(0);					\
		} else if (pid > 0) {					\
			_parent_;					\
			rpid = waitpid(pid, &ret, 0);			\
			ASSERT_RETURN(rpid == pid);			\
			ASSERT_RETURN(WIFEXITED(ret));			\
			ASSERT_RETURN(WEXITSTATUS(ret) == 0);		\
			ret = TEST_OK;					\
		} else {						\
			ret = pid;					\
		}							\
									\
		ret;							\
	})

#define RUN_UNPRIVILEGED_CONN(_var_, _bus_, _code_)			\
	RUN_UNPRIVILEGED(({						\
		struct kdbus_conn *_var_;				\
		_var_ = kdbus_hello(_bus_, 0, NULL, 0);			\
		ASSERT_EXIT(_var_);					\
		_code_;							\
		kdbus_conn_free(_var_);					\
	}), ({ 0; }))

static void nosig(int sig)
{
}

static int test_policy_priv(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn_a, *conn_b, *conn, *owner;
	struct kdbus_policy_access access, *acc;
	cap_flag_value_t flag_setuid, flag_setgid;
	sigset_t sset;
	size_t num;
	cap_t cap;
	int ret;

	/*
	 * Make sure we have CAP_SETUID/SETGID so we can drop privileges
	 */

	cap = cap_get_proc();
	ASSERT_RETURN(cap);

	ret = cap_get_flag(cap, CAP_SETUID, CAP_EFFECTIVE, &flag_setuid);
	ASSERT_RETURN(ret >= 0);
	ret = cap_get_flag(cap, CAP_SETGID, CAP_EFFECTIVE, &flag_setgid);
	ASSERT_RETURN(ret >= 0);

	if (flag_setuid != CAP_SET || flag_setgid != CAP_SET)
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

	/*
	 * Make sure that unprivileged users cannot acquire names
	 * before registring any policy holder.
	 */
	ret = RUN_UNPRIVILEGED_CONN(unpriv, env->buspath, ({
		ret = kdbus_name_acquire(unpriv, "com.example.a", NULL);
		ASSERT_EXIT(ret < 0);
	}));
	ASSERT_RETURN(ret >= 0);

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

	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn);

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
	ret = kdbus_msg_recv_poll(conn_b, 100, NULL, NULL);
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
	ASSERT_EXIT(ret >= 0);

	ret = RUN_UNPRIVILEGED(({
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
