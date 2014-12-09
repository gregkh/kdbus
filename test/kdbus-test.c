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

struct kdbus_test_args {
	int loop;
	int wait;
	int fork;
	char *module;
	char *root;
	char *test;
	char *busname;
	char *mask_param_path;
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
	{
		/* Last test */
		.name	= "attach-flags",
		.desc	= "attach flags mask",
		.func	= kdbus_test_attach_flags,
		.flags	= 0,
	},
	{ NULL } /* sentinel */
};

static int test_prepare_env(const struct kdbus_test *t,
			    const struct kdbus_test_args *args,
			    struct kdbus_test_env *env)
{
	if (t->flags & TEST_CREATE_BUS) {
		char *s;
		char *n = NULL;
		int ret;

		asprintf(&s, "%s/control", args->root);

		env->control_fd = open(s, O_RDWR);
		free(s);
		ASSERT_RETURN(env->control_fd >= 0);

		if (!args->busname) {
			n = unique_name("test-bus");
			ASSERT_RETURN(n);
		}

		ret = kdbus_create_bus(env->control_fd,
				       args->busname ?: n,
				       _KDBUS_ATTACH_ALL,
				       _KDBUS_ATTACH_ALL, &s);
		free(n);
		ASSERT_RETURN(ret == 0);

		asprintf(&env->buspath, "%s/%s/bus", args->root, s);
		free(s);
	}

	if (t->flags & TEST_CREATE_CONN) {
		env->conn = kdbus_hello(env->buspath, 0, NULL, 0);
		ASSERT_RETURN(env->conn);
	}

	env->root = args->root;
	env->module = args->module;
	env->mask_param_path = args->mask_param_path;

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

static int test_run(const struct kdbus_test *t,
		    const struct kdbus_test_args *kdbus_args,
		    int wait)
{
	int ret;
	struct kdbus_test_env env = {};

	ret = test_prepare_env(t, kdbus_args, &env);
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

static int test_run_forked(const struct kdbus_test *t,
			   const struct kdbus_test_args *kdbus_args,
			   int wait)
{
	int ret;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		return TEST_ERR;
	} else if (pid == 0) {
		ret = test_run(t, kdbus_args, wait);
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

static int start_all_tests(struct kdbus_test_args *kdbus_args)
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

		ret = test_run_forked(t, kdbus_args, 0);
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

	return fail_cnt > 0 ? TEST_ERR : TEST_OK;
}

static int start_one_test(struct kdbus_test_args *kdbus_args)
{
	int ret;
	bool test_found = false;
	const struct kdbus_test *t;

	for (t = tests; t->name; t++) {
		if (strcmp(t->name, kdbus_args->test))
			continue;

		do {
			test_found = true;
			if (kdbus_args->fork)
				ret = test_run_forked(t, kdbus_args,
						      kdbus_args->wait);
			else
				ret = test_run(t, kdbus_args,
					       kdbus_args->wait);

			printf("Testing %s: ", t->desc);
			print_test_result(ret);
			printf("\n");

			if (ret != TEST_OK)
				break;
		} while (kdbus_args->loop);

		return ret;
	}

	if (!test_found) {
		printf("Unknown test-id '%s'\n", kdbus_args->test);
		return TEST_ERR;
	}

	return TEST_OK;
}

static void usage(const char *argv0)
{
	const struct kdbus_test *t;
	unsigned int i;

	printf("Usage: %s [options]\n"
	       "Options:\n"
	       "\t-m, --module <module>	Kdbus module name\n"
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

int start_tests(struct kdbus_test_args *kdbus_args)
{
	static char fspath[4096], parampath[4096], control[4096];
	int ret;

	if (!kdbus_args->module)
		kdbus_args->module = "kdbus";

	if (!kdbus_args->root) {
		snprintf(fspath, sizeof(fspath), "/sys/fs/%s",
			 kdbus_args->module);
		kdbus_args->root = fspath;
	}

	snprintf(parampath, sizeof(parampath),
		 "/sys/module/%s/parameters/attach_flags_mask",
		 kdbus_args->module);
	kdbus_args->mask_param_path = parampath;

	snprintf(control, sizeof(control), "%s/control", kdbus_args->root);

	if (access(control, W_OK) < 0) {
		printf("Unable to locate control node at '%s'.\n",
			control);
		return TEST_ERR;
	}

	if (kdbus_args->test) {
		ret = start_one_test(kdbus_args);
	} else {
		do {
			ret = start_all_tests(kdbus_args);
			if (ret != TEST_OK)
				break;
		} while (kdbus_args->loop);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int t, ret = 0;
	struct kdbus_test_args *kdbus_args;

	kdbus_args = malloc(sizeof(*kdbus_args));
	if (!kdbus_args) {
		printf("unable to malloc() kdbus_args\n");
		return EXIT_FAILURE;
	}

	memset(kdbus_args, 0, sizeof(*kdbus_args));

	static const struct option options[] = {
		{ "loop",	no_argument,		NULL, 'x' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "root",	required_argument,	NULL, 'r' },
		{ "test",	required_argument,	NULL, 't' },
		{ "bus",	required_argument,	NULL, 'b' },
		{ "wait",	required_argument,	NULL, 'w' },
		{ "fork",	no_argument,		NULL, 'f' },
		{ "module",	required_argument,	NULL, 'm' },
		{}
	};

	srand(time(NULL));

	while ((t = getopt_long(argc, argv, "hxfm:r:t:b:w:", options, NULL)) >= 0) {
		switch (t) {
		case 'x':
			kdbus_args->loop = 1;
			break;

		case 'm':
			kdbus_args->module = optarg;
			break;

		case 'r':
			kdbus_args->root = optarg;
			break;

		case 't':
			kdbus_args->test = optarg;
			break;

		case 'b':
			kdbus_args->busname = optarg;
			break;

		case 'w':
			kdbus_args->wait = strtol(optarg, NULL, 10);
			break;

		case 'f':
			kdbus_args->fork = 1;
			break;

		default:
		case 'h':
			usage(argv[0]);
		}
	}

	ret = start_tests(kdbus_args);
	if (ret == TEST_ERR)
		return EXIT_FAILURE;

	free(kdbus_args);

	return 0;
}
