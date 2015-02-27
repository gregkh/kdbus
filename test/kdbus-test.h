#ifndef _TEST_KDBUS_H_
#define _TEST_KDBUS_H_

struct kdbus_test_env {
	char *buspath;
	const char *root;
	const char *module;
	const char *mask_param_path;
	int control_fd;
	struct kdbus_conn *conn;
};

enum {
	TEST_OK,
	TEST_SKIP,
	TEST_ERR,
};

#define ASSERT_RETURN_VAL(cond, val)		\
	if (!(cond)) {			\
		fprintf(stderr,	"Assertion '%s' failed in %s(), %s:%d\n", \
			#cond, __func__, __FILE__, __LINE__);	\
		return val;	\
	}

#define ASSERT_EXIT_VAL(cond, val)		\
	if (!(cond)) {			\
		fprintf(stderr, "Assertion '%s' failed in %s(), %s:%d\n", \
			#cond, __func__, __FILE__, __LINE__);	\
		_exit(val);	\
	}

#define ASSERT_BREAK(cond)		\
	if (!(cond)) {			\
		fprintf(stderr, "Assertion '%s' failed in %s(), %s:%d\n", \
			#cond, __func__, __FILE__, __LINE__);	\
		break; \
	}

#define ASSERT_RETURN(cond)		\
	ASSERT_RETURN_VAL(cond, TEST_ERR)

#define ASSERT_EXIT(cond)		\
	ASSERT_EXIT_VAL(cond, EXIT_FAILURE)

int kdbus_test_activator(struct kdbus_test_env *env);
int kdbus_test_attach_flags(struct kdbus_test_env *env);
int kdbus_test_benchmark(struct kdbus_test_env *env);
int kdbus_test_benchmark_nomemfds(struct kdbus_test_env *env);
int kdbus_test_benchmark_uds(struct kdbus_test_env *env);
int kdbus_test_bus_make(struct kdbus_test_env *env);
int kdbus_test_byebye(struct kdbus_test_env *env);
int kdbus_test_chat(struct kdbus_test_env *env);
int kdbus_test_conn_info(struct kdbus_test_env *env);
int kdbus_test_conn_update(struct kdbus_test_env *env);
int kdbus_test_daemon(struct kdbus_test_env *env);
int kdbus_test_custom_endpoint(struct kdbus_test_env *env);
int kdbus_test_fd_passing(struct kdbus_test_env *env);
int kdbus_test_free(struct kdbus_test_env *env);
int kdbus_test_hello(struct kdbus_test_env *env);
int kdbus_test_match_bloom(struct kdbus_test_env *env);
int kdbus_test_match_id_add(struct kdbus_test_env *env);
int kdbus_test_match_id_remove(struct kdbus_test_env *env);
int kdbus_test_match_replace(struct kdbus_test_env *env);
int kdbus_test_match_name_add(struct kdbus_test_env *env);
int kdbus_test_match_name_change(struct kdbus_test_env *env);
int kdbus_test_match_name_remove(struct kdbus_test_env *env);
int kdbus_test_message_basic(struct kdbus_test_env *env);
int kdbus_test_message_prio(struct kdbus_test_env *env);
int kdbus_test_message_quota(struct kdbus_test_env *env);
int kdbus_test_memory_access(struct kdbus_test_env *env);
int kdbus_test_metadata_ns(struct kdbus_test_env *env);
int kdbus_test_monitor(struct kdbus_test_env *env);
int kdbus_test_name_basic(struct kdbus_test_env *env);
int kdbus_test_name_conflict(struct kdbus_test_env *env);
int kdbus_test_name_queue(struct kdbus_test_env *env);
int kdbus_test_policy(struct kdbus_test_env *env);
int kdbus_test_policy_ns(struct kdbus_test_env *env);
int kdbus_test_policy_priv(struct kdbus_test_env *env);
int kdbus_test_sync_byebye(struct kdbus_test_env *env);
int kdbus_test_sync_reply(struct kdbus_test_env *env);
int kdbus_test_timeout(struct kdbus_test_env *env);
int kdbus_test_writable_pool(struct kdbus_test_env *env);

#endif /* _TEST_KDBUS_H_ */
