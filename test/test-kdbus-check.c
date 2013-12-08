#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "kdbus-util.h"
#include "kdbus-enum.h"

enum {
	CHECK_OK,
	CHECK_SKIP,
	CHECK_ERR,
};

enum {
	CHECK_CREATE_BUS	= 1 << 0,
	CHECK_CREATE_CONN	= 1 << 1,
};

struct kdbus_conn {
	int fd;
	struct kdbus_cmd_hello hello;
	void *buf;
	size_t size;
};

struct kdbus_check_env {
	char *buspath;
	int control_fd;
	struct kdbus_conn *conn;
};


struct kdbus_check {
	const char *name;
	int (*func)(struct kdbus_check_env *env);
	unsigned int flags;
};

#define POOL_SIZE (16 * 1024LU * 1024LU)
#define ATTACH_FLAGS 	KDBUS_ATTACH_TIMESTAMP	|	\
			KDBUS_ATTACH_CREDS	|	\
			KDBUS_ATTACH_NAMES	|	\
			KDBUS_ATTACH_COMM	|	\
			KDBUS_ATTACH_EXE	|	\
			KDBUS_ATTACH_CMDLINE	|	\
			KDBUS_ATTACH_CAPS	|	\
			KDBUS_ATTACH_CGROUP	|	\
			KDBUS_ATTACH_SECLABEL	|	\
			KDBUS_ATTACH_AUDIT

#define ASSERT_RETURN(cond)		\
	if (!(cond)) {			\
		fprintf(stderr, "Assertion '%s' failed in %s(), line %d\n", #cond, __func__, __LINE__);	\
		return CHECK_ERR;	\
	}

static struct kdbus_conn *make_conn(const char *buspath)
{
	int ret;
	struct kdbus_conn *conn;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		fprintf(stderr, "unable to malloc()!?\n");
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));

	conn->fd = open(buspath, O_RDWR|O_CLOEXEC);
	if (conn->fd < 0) {
		fprintf(stderr, "--- error %d (%m)\n", conn->fd);
		return NULL;
	}

	conn->hello.conn_flags = KDBUS_HELLO_ACCEPT_FD;

	conn->hello.attach_flags = KDBUS_ATTACH_TIMESTAMP |
				   KDBUS_ATTACH_CREDS |
				   KDBUS_ATTACH_NAMES |
				   KDBUS_ATTACH_COMM |
				   KDBUS_ATTACH_EXE |
				   KDBUS_ATTACH_CMDLINE |
				   KDBUS_ATTACH_CAPS |
				   KDBUS_ATTACH_CGROUP |
				   KDBUS_ATTACH_SECLABEL |
				   KDBUS_ATTACH_AUDIT;

	conn->hello.size = sizeof(struct kdbus_cmd_hello);
	conn->hello.pool_size = POOL_SIZE;

	ret = ioctl(conn->fd, KDBUS_CMD_HELLO, &conn->hello);
	if (ret < 0) {
		fprintf(stderr, "--- error when saying hello: %d (%m)\n", ret);
		return NULL;
	}

	conn->buf = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, conn->fd, 0);
	if (conn->buf == MAP_FAILED) {
		free(conn);
		fprintf(stderr, "--- error mmap (%m)\n");
		return NULL;
	}

	return conn;
}

static int conn_is_name_owner(const struct kdbus_conn *conn, uint64_t flags, const char *n)
{
	struct kdbus_cmd_name_list cmd_list;
	struct kdbus_name_list *list;
	struct kdbus_cmd_name *name;
	int found = 0;
	int ret;

	cmd_list.flags = flags;

	ret = ioctl(conn->fd, KDBUS_CMD_NAME_LIST, &cmd_list);
	ASSERT_RETURN(ret == 0);

	list = (struct kdbus_name_list *)(conn->buf + cmd_list.offset);
	KDBUS_ITEM_FOREACH(name, list, names) {
		if (name->size == sizeof(struct kdbus_cmd_name))
			continue;

		if (name->id == conn->hello.id && strcmp(n, name->name) == 0) {
			found = 1;
			break;
		}
	}

	ret = ioctl(conn->fd, KDBUS_CMD_FREE, &cmd_list.offset);
	ASSERT_RETURN(ret == 0);

	return found ? 0 : -1;
}

/* -----------------------------------8<------------------------------- */

static int check_hello(struct kdbus_check_env *env)
{
	struct kdbus_cmd_hello hello;
	int fd, ret;

	memset(&hello, 0, sizeof(hello));

	fd = open(env->buspath, O_RDWR|O_CLOEXEC);
	if (fd < 0)
		return CHECK_ERR;

	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD;
	hello.attach_flags = ATTACH_FLAGS;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;

	/* an unaligned hello must result in -EFAULT */
	ret = ioctl(fd, KDBUS_CMD_HELLO, (char *) &hello + 1);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	/* a size of 0 must return EMSGSIZE */
	hello.size = 1;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EMSGSIZE);

	hello.size = sizeof(struct kdbus_cmd_hello);

	/* check faulty flags */
	hello.conn_flags = 1ULL << 32;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == 524);

	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD;

	/* check for faulty pool sizes */
	hello.pool_size = 0;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	hello.pool_size = 4097;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EFAULT);

	hello.pool_size = POOL_SIZE;

	/* success test */
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == 0);

	close(fd);
	fd = open(env->buspath, O_RDWR|O_CLOEXEC);
	ASSERT_RETURN(fd >= 0);

	/* no STARTER flag without a name */
	hello.conn_flags = KDBUS_HELLO_STARTER;
	ret = ioctl(fd, KDBUS_CMD_HELLO, &hello);
	ASSERT_RETURN(ret == -1 && errno == EINVAL);

	return CHECK_OK;
}

static int check_name_basic(struct kdbus_check_env *env)
{
	struct kdbus_cmd_name *cmd_name;
	uint64_t size;
	char *name;
	int ret;

	name = "foo.bla.blaz";
	ret = upload_policy(env->conn->fd, name);
	ASSERT_RETURN(ret == 0);

	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = 0;

	/* check that we can acquire a name */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, KDBUS_NAME_LIST_NAMES, name);
	ASSERT_RETURN(ret == 0);

	/* ... and release it again */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, KDBUS_NAME_LIST_NAMES, name);
	ASSERT_RETURN(ret != 0);

	/* check that we can't release it again */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	ASSERT_RETURN(ret == -1 && errno == ESRCH);

	/* check that we can't release a name that we don't own */
	cmd_name->name[0] = 'x';
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	ASSERT_RETURN(ret == -1 && errno == ESRCH);

	return CHECK_OK;
}

static int check_name_conflict(struct kdbus_check_env *env)
{
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_conn *conn;
	uint64_t size;
	char *name;
	int ret;

	name = "foo.bla.blaz";
	ret = upload_policy(env->conn->fd, name);
	ASSERT_RETURN(ret == 0);

	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = 0;

	/* create a 2nd connection */
	conn = make_conn(env->buspath);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	ret = upload_policy(conn->fd, name);
	ASSERT_RETURN(ret == 0);

	/* acquire name from the 1st connection */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, KDBUS_NAME_LIST_NAMES, name);
	ASSERT_RETURN(ret == 0);

	/* check that we can't acquire it again from the 1st connection */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == -1 && errno == EALREADY);

	/* check that we also can't acquire it again from the 2nd connection */
	ret = ioctl(conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == -1 && errno == EEXIST);

	return CHECK_OK;
}

static int check_name_queue(struct kdbus_check_env *env)
{
	struct kdbus_cmd_name *cmd_name;
	struct kdbus_conn *conn;
	uint64_t size;
	char *name;
	int ret;

	name = "foo.bla.blaz";
	ret = upload_policy(env->conn->fd, name);
	ASSERT_RETURN(ret == 0);

	size = sizeof(*cmd_name) + strlen(name) + 1;
	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;
	cmd_name->flags = KDBUS_NAME_ALLOW_REPLACEMENT;

	/* create a 2nd connection */
	conn = make_conn(env->buspath);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	ret = upload_policy(conn->fd, name);
	ASSERT_RETURN(ret == 0);

	/* acquire name from the 1st connection */
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_owner(env->conn, KDBUS_NAME_LIST_NAMES, name);
	ASSERT_RETURN(ret == 0);

	/* queue the 2nd connection as waiting owner */
	cmd_name->flags = KDBUS_NAME_QUEUE;
	ret = ioctl(conn->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name);
	ASSERT_RETURN(ret == 0);

	/* release name from 1st connection */
	cmd_name->flags = 0;
	ret = ioctl(env->conn->fd, KDBUS_CMD_NAME_RELEASE, cmd_name);
	ASSERT_RETURN(ret == 0);

	return CHECK_OK;
}

/* -----------------------------------8<------------------------------- */

static int check_prepare_env(const struct kdbus_check *c, struct kdbus_check_env *env)
{
	if (c->flags & CHECK_CREATE_BUS) {
		struct {
			struct kdbus_cmd_bus_make head;

			/* name item */
			uint64_t n_size;
			uint64_t n_type;
			char name[64];
		} __attribute__ ((__aligned__(8))) bus_make;
		unsigned int i;
		char n[32];
		int ret;

		env->control_fd = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
		ASSERT_RETURN(env->control_fd >= 0);

		memset(&bus_make, 0, sizeof(bus_make));
		bus_make.head.bloom_size = 64;

		for (i = 0; i < sizeof(n); i++)
			n[i] = 'a' + (random() % ('z' - 'a'));

		snprintf(bus_make.name, sizeof(bus_make.name), "%u-%s", getuid(), n);

		bus_make.n_type = KDBUS_ITEM_MAKE_NAME;
		bus_make.n_size = KDBUS_ITEM_HEADER_SIZE + strlen(bus_make.name) + 1;

		bus_make.head.size = sizeof(struct kdbus_cmd_bus_make) +
				     bus_make.n_size;

		ret = ioctl(env->control_fd, KDBUS_CMD_BUS_MAKE, &bus_make);
		ASSERT_RETURN(ret == 0);

		ret = asprintf(&env->buspath, "/dev/kdbus/%s/bus", bus_make.name);
		ASSERT_RETURN(ret >= 0);
	}

	if (c->flags & CHECK_CREATE_CONN) {
		env->conn = make_conn(env->buspath);
		if (!env->conn)
			return EXIT_FAILURE;
	}

	return 0;
}

void check_unprepare_env(const struct kdbus_check *c, struct kdbus_check_env *env)
{
	if (env->conn) {
		if (env->conn->fd >= 0)
			close(env->conn->fd);

		free(env->conn);
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

static const struct kdbus_check checks[] = {
	{ "hello",		check_hello,		CHECK_CREATE_BUS			},
	{ "name basics",	check_name_basic,	CHECK_CREATE_BUS | CHECK_CREATE_CONN	},
	{ "name conflict",	check_name_conflict,	CHECK_CREATE_BUS | CHECK_CREATE_CONN	},
	{ "name queue",		check_name_queue,	CHECK_CREATE_BUS | CHECK_CREATE_CONN	},
	{ NULL, NULL, 0 }
};

int main(int argc, char *argv[])
{
	int ret;
	unsigned int fail_cnt = 0;
	unsigned int skip_cnt = 0;
	unsigned int ok_cnt = 0;
	unsigned int i;
	const struct kdbus_check *c;
	struct kdbus_check_env env;

	memset(&env, 0, sizeof(env));

	for (c = checks; c->name; c++) {
		ret = check_prepare_env(c, &env);
		if (ret != 0) {
			printf("PREPARATION OF TEST '%s' FAILED!\n", c->name);
			fail_cnt++;
			continue;
		}

		printf("RUNING TEST '%s' ", c->name);
		for (i = 0; i < 30 - strlen(c->name); i++)
			printf(".");
		printf(" ");

		ret = c->func(&env);

		switch (ret) {
		case CHECK_OK:
			printf("OK");
			ok_cnt++;
			break;
		case CHECK_SKIP:
			printf("SKIPPED");
			skip_cnt++;
			break;
		case CHECK_ERR:
			printf("ERROR");
			fail_cnt++;
			break;
		}

		printf("\n");

		check_unprepare_env(c, &env);
	}

	printf("\nSUMMARY: %d tests passed, %d skipped, %d failed\n", ok_cnt, skip_cnt, fail_cnt);

	return fail_cnt > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
