#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/wait.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

enum {
	TEST_CREATE_BUS		= 1 << 0,
	TEST_CREATE_CONN	= 1 << 1,
};

struct kdbus_test {
	const char *name;
	const char *desc;
	int (*func)(struct kdbus_test_env *env);
	unsigned int flags;
};

static const struct kdbus_test tests[] = {
	{
		.name	= "bus-make",
		.desc	= "bus make functions",
		.func	= kdbus_test_bus_make,
		.flags	= 0,
	},
	{
		.name	= "hello",
		.desc	= "the HELLO command",
		.func	= kdbus_test_hello,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "byebye",
		.desc	= "the BYEBYE command",
		.func	= kdbus_test_byebye,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "chat",
		.desc	= "a chat pattern",
		.func	= kdbus_test_chat,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "daemon",
		.desc	= "a simple dameon",
		.func	= kdbus_test_daemon,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "fd-passing",
		.desc	= "file descriptor passing",
		.func	= kdbus_test_fd_passing,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "endpoint",
		.desc	= "custom endpoint",
		.func	= kdbus_test_custom_endpoint,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "monitor",
		.desc	= "monitor functionality",
		.func	= kdbus_test_monitor,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "name-basics",
		.desc	= "basic name registry functions",
		.func	= kdbus_test_name_basic,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "name-conflict",
		.desc	= "name registry conflict details",
		.func	= kdbus_test_name_conflict,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "name-queue",
		.desc	= "queuing of names",
		.func	= kdbus_test_name_queue,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "message-basic",
		.desc	= "basic message handling",
		.func	= kdbus_test_message_basic,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "message-prio",
		.desc	= "handling of messages with priority",
		.func	= kdbus_test_message_prio,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "message-quota",
		.desc	= "message quotas are enforced",
		.func	= kdbus_test_message_quota,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "timeout",
		.desc	= "timeout",
		.func	= kdbus_test_timeout,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "sync-byebye",
		.desc	= "synchronous replies vs. BYEBYE",
		.func	= kdbus_test_sync_byebye,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "sync-reply",
		.desc	= "synchronous replies",
		.func	= kdbus_test_sync_reply,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "message-free",
		.desc	= "freeing of memory",
		.func	= kdbus_test_free,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "connection-info",
		.desc	= "retrieving connection information",
		.func	= kdbus_test_conn_info,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "connection-update",
		.desc	= "updating connection information",
		.func	= kdbus_test_conn_update,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "writable-pool",
		.desc	= "verifying pools are never writable",
		.func	= kdbus_test_writable_pool,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "policy",
		.desc	= "policy",
		.func	= kdbus_test_policy,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "policy-priv",
		.desc	= "unprivileged bus access",
		.func	= kdbus_test_policy_priv,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "policy-ns",
		.desc	= "policy in user namespaces",
		.func	= kdbus_test_policy_ns,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "metadata-ns",
		.desc	= "metadata in user namespaces",
		.func	= kdbus_test_metadata_ns,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-id-add",
		.desc	= "adding of matches by id",
		.func	= kdbus_test_match_id_add,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-id-remove",
		.desc	= "removing of matches by id",
		.func	= kdbus_test_match_id_remove,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-replace",
		.desc	= "replace of matches with the same cookie",
		.func	= kdbus_test_match_replace,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-name-add",
		.desc	= "adding of matches by name",
		.func	= kdbus_test_match_name_add,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-name-remove",
		.desc	= "removing of matches by name",
		.func	= kdbus_test_match_name_remove,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-name-change",
		.desc	= "matching for name changes",
		.func	= kdbus_test_match_name_change,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "match-bloom",
		.desc	= "matching with bloom filters",
		.func	= kdbus_test_match_bloom,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "activator",
		.desc	= "activator connections",
		.func	= kdbus_test_activator,
		.flags	= TEST_CREATE_BUS | TEST_CREATE_CONN,
	},
	{
		.name	= "benchmark",
		.desc	= "benchmark",
		.func	= kdbus_test_benchmark,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "race-byebye",
		.desc	= "race multiple byebyes",
		.func	= kdbus_test_race_byebye,
		.flags	= TEST_CREATE_BUS,
	},
	{
		.name	= "race-byebye-match",
		.desc	= "race byebye vs match removal",
		.func	= kdbus_test_race_byebye_match,
		.flags	= TEST_CREATE_BUS,
	},
	{ NULL } /* sentinel */
};

static int test_prepare_env(const struct kdbus_test *t,
			    struct kdbus_test_env *env,
			    const char *root,
			    const char *busname)
{
	if (t->flags & TEST_CREATE_BUS) {
		char *s, *n;
		int ret;

		asprintf(&s, "%s/control", root);

		env->control_fd = open(s, O_RDWR);
		free(s);
		ASSERT_RETURN(env->control_fd >= 0);

		if (!busname) {
			n = unique_name("test-bus");
			ASSERT_RETURN(n);
		}

		ret = kdbus_create_bus(env->control_fd, busname ?: n,
				       _KDBUS_ATTACH_ALL, &s);
		ASSERT_RETURN(ret == 0);

		asprintf(&env->buspath, "%s/%s/bus", root, s);
		free(s);
	}

	if (t->flags & TEST_CREATE_CONN) {
		env->conn = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(env->conn);
	}

	env->root = root;

	return 0;
}

void test_unprepare_env(const struct kdbus_test *t, struct kdbus_test_env *env)
{
	if (env->conn) {
		kdbus_conn_free(env->conn);
		env->conn = NULL;
	}

	if (env->control_fd >= 0) {
		close(env->control_fd);
		env->control_fd = -1;
	}

	if (env->buspath) {
		free(env->buspath);
		env->buspath = NULL;
	}
}

static int test_run(const struct kdbus_test *t, const char *root,
		    const char *busname, int wait)
{
	int ret;
	struct kdbus_test_env env = {};

	ret = test_prepare_env(t, &env, root, busname);
	if (ret != TEST_OK)
		return ret;

	if (wait > 0) {
		printf("Sleeping %d seconds before running test ...\n", wait);
		sleep(wait);
	}

	ret = t->func(&env);
	test_unprepare_env(t, &env);
	return ret;
}

static int test_run_forked(const struct kdbus_test *t, const char *root,
			   const char *busname, int wait)
{
	int ret;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		return TEST_ERR;
	} else if (pid == 0) {
		ret = test_run(t, root, busname, wait);
		_exit(ret);
	}

	pid = waitpid(pid, &ret, 0);
	if (pid <= 0)
		return TEST_ERR;
	else if (!WIFEXITED(ret))
		return TEST_ERR;
	else
		return WEXITSTATUS(ret);
}

static void print_test_result(int ret)
{
	switch (ret) {
	case TEST_OK:
		printf("OK");
		break;
	case TEST_SKIP:
		printf("SKIPPED");
		break;
	case TEST_ERR:
		printf("ERROR");
		break;
	}
}

static int run_all_tests(const char *root, const char *busname)
{
	int ret;
	unsigned int fail_cnt = 0;
	unsigned int skip_cnt = 0;
	unsigned int ok_cnt = 0;
	unsigned int i;
	const struct kdbus_test *t;

	kdbus_util_verbose = false;

	for (t = tests; t->name; t++) {
		printf("Testing %s (%s) ", t->desc, t->name);
		for (i = 0; i < 60 - strlen(t->desc) - strlen(t->name); i++)
			printf(".");
		printf(" ");

		ret = test_run_forked(t, root, busname, 0);
		switch (ret) {
		case TEST_OK:
			ok_cnt++;
			break;
		case TEST_SKIP:
			skip_cnt++;
			break;
		case TEST_ERR:
			fail_cnt++;
			break;
		}

		print_test_result(ret);
		printf("\n");
	}

	printf("\nSUMMARY: %d tests passed, %d skipped, %d failed\n",
	       ok_cnt, skip_cnt, fail_cnt);

	return fail_cnt > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void usage(const char *argv0)
{
	const struct kdbus_test *t;
	unsigned int i;

	printf("Usage: %s [options]\n"
	       "Options:\n"
	       "\t-x, --loop		Run in a loop\n"
	       "\t-f, --fork		Fork before running a test\n"
	       "\t-h, --help		Print this help\n"
	       "\t-r, --root <root>	Toplevel of the kdbus hierarchy\n"
	       "\t-t, --test <test-id>	Run one specific test only, in verbose mode\n"
	       "\t-b, --bus <busname>	Instead of generating a random bus name, take <busname>.\n"
	       "\t-w, --wait <secs>	Wait <secs> before actually starting test\n"
	       "\n", argv0);

	printf("By default, all test are run once, and a summary is printed.\n"
	       "Available tests for --test:\n\n");

	for (t = tests; t->name; t++) {
		printf("\t%s", t->name);

		for (i = 0; i < 24 - strlen(t->name); i++)
			printf(" ");

		printf("Test %s\n", t->desc);
	}

	printf("\n");
	printf("Note that some tests may, if run specifically by --test, "
	       "behave differently, and not terminate by themselves.\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int t, ret = 0;
	int arg_loop = 0;
	char *arg_root = NULL;
	char *arg_test = NULL;
	char *arg_busname = NULL;
	int arg_wait = 0;
	int arg_fork = 0;
	char *control;

	static const struct option options[] = {
		{ "loop",	no_argument,		NULL, 'x' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "root",	required_argument,	NULL, 'r' },
		{ "test",	required_argument,	NULL, 't' },
		{ "bus",	required_argument,	NULL, 'b' },
		{ "wait",	required_argument,	NULL, 'w' },
		{ "fork",	no_argument,		NULL, 'f' },
		{}
	};

	srand(time(NULL));

	while ((t = getopt_long(argc, argv, "hxfr:t:b:w:", options, NULL)) >= 0) {
		switch (t) {
		case 'x':
			arg_loop = 1;
			break;

		case 'r':
			arg_root = optarg;
			break;

		case 't':
			arg_test = optarg;
			break;

		case 'b':
			arg_busname = optarg;
			break;

		case 'w':
			arg_wait = strtol(optarg, NULL, 10);
			break;

		case 'f':
			arg_fork = 1;
			break;

		default:
		case 'h':
			usage(argv[0]);
		}
	}

	if (!arg_root)
		arg_root = "/sys/fs/kdbus";

	asprintf(&control, "%s/control", arg_root);

	if (access(control, W_OK) < 0) {
		printf("Unable to locate control node at '%s'.\n", control);
		return EXIT_FAILURE;
	}

	free(control);

	if (arg_test) {
		const struct kdbus_test *t;

		for (t = tests; t->name; t++) {
			if (!strcmp(t->name, arg_test)) {
				do {
					if (arg_fork)
						ret = test_run_forked(t,
								arg_root,
								arg_busname,
								arg_wait);
					else
						ret = test_run(t, arg_root,
							       arg_busname,
							       arg_wait);
					printf("Testing %s: ", t->desc);
					print_test_result(ret);
					printf("\n");

					if (ret != TEST_OK)
						break;
				} while (arg_loop);

				return ret == TEST_OK ? 0 : EXIT_FAILURE;
			}
		}

		printf("Unknown test-id '%s'\n", arg_test);
		return EXIT_FAILURE;
	}

	do {
		ret = run_all_tests(arg_root, arg_busname);
		if (ret != TEST_OK)
			break;
	} while (arg_loop);

	return 0;
}
