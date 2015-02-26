/*
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/*
 * Example: Workers
 * This program computes prime-numbers based on the sieve of Eratosthenes. The
 * master sets up a shared memory region and spawns workers which clear out the
 * non-primes. The master reacts to keyboard input and to client-requests to
 * control what each worker does. Note that this is in no way meant as efficient
 * way to compute primes. It should only serve as example how a master/worker
 * concept can be implemented with kdbus used as control messages.
 *
 * The main process is called the 'master'. It creates a new, private bus which
 * will be used between the master and its workers to communicate. The master
 * then spawns a fixed number of workers. Whenever a worker dies (detected via
 * SIGCHLD), the master spawns a new worker. When done, the master waits for all
 * workers to exit, prints a status report and exits itself.
 *
 * The master process does *not* keep track of its workers. Instead, this
 * example implements a PULL model. That is, the master acquires a well-known
 * name on the bus which each worker uses to request tasks from the master. If
 * there are no more tasks, the master will return an empty task-list, which
 * casues a worker to exit immediately.
 *
 * As tasks can be computationally expensive, we support cancellation. Whenever
 * the master process is interrupted, it will drop its well-known name on the
 * bus. This causes kdbus to broadcast a name-change notification. The workers
 * check for broadcast messages regularly and will exit if they receive one.
 *
 * This example exists of 4 objects:
 *  * master: The master object contains the context of the master process. This
 *            process manages the prime-context, spawns workers and assigns
 *            prime-ranges to each worker to compute.
 *            The master itself does not do any prime-computations itself.
 *  * child: The child object contains the context of a worker. It inherits the
 *           prime context from its parent (the master) and then creates a new
 *           bus context to request prime-ranges to compute.
 *  * prime: The "prime" object is used to abstract how we compute primes. When
 *           allocated, it prepares a memory region to hold 1 bit for each
 *           natural number up to a fixed maximum ('MAX_PRIMES').
 *           The memory region is backed by a memfd which we share between
 *           processes. Each worker now gets assigned a range of natural numbers
 *           which it clears multiples of off the memory region. The master
 *           process is responsible of distributing all natural numbers up to
 *           the fixed maximum to its workers.
 *  * bus: The bus object is an abstraction of the kdbus API. It is pretty
 *         straightfoward and only manages the connection-fd plus the
 *         memory-mapped pool in a single object.
 *
 * This example is in reversed order, which should make it easier to read
 * top-down, but requires some forward-declarations. Just ignore those.
 *
 * TODO: properly document this example
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "kdbus-api.h"

/* FORWARD DECLARATIONS */

#define POOL_SIZE (16 * 1024 * 1024)
#define MAX_PRIMES (2UL << 24)
#define WORKER_COUNT (16)
#define PRIME_STEPS (65536 * 4)

static const char *arg_busname = "example-workers";
static const char *arg_modname = "kdbus";
static const char *arg_master = "org.freedesktop.master";

static int err_assert(int r_errno, const char *msg, const char *func, int line,
		      const char *file)
{
	r_errno = (r_errno != 0) ? -abs(r_errno) : -EFAULT;
	if (r_errno < 0) {
		errno = -r_errno;
		fprintf(stderr, "ERR: %s: %m (%s:%d in %s)\n",
			msg, func, line, file);
	}
	return r_errno;
}

#define err_r(_r, _msg) err_assert((_r), (_msg), __func__, __LINE__, __FILE__)
#define err(_msg) err_r(errno, (_msg))

struct prime;
struct bus;
struct master;
struct child;

struct prime {
	int fd;
	uint8_t *area;
	size_t max;
	size_t done;
	size_t status;
};

static int prime_new(struct prime **out);
static void prime_free(struct prime *p);
static bool prime_done(struct prime *p);
static void prime_consume(struct prime *p, size_t amount);
static int prime_run(struct prime *p, struct bus *cancel, size_t number);
static void prime_print(struct prime *p);

struct bus {
	int fd;
	uint8_t *pool;
};

static int bus_open(struct bus **out, uid_t uid, const char *name,
		    uint64_t recv_flags);
static void bus_close(struct bus *b);
static void bus_release(struct bus *b, uint64_t offset);
static int bus_acquire(struct bus *b, const char *name);
static int bus_install(struct bus *b, const char *name);
static int bus_poll(struct bus *b);
static int bus_make(uid_t uid, const char *name);

struct master {
	size_t n_workers;
	size_t max_workers;

	int signal_fd;
	int control_fd;

	struct prime *prime;
	struct bus *bus;
};

static int master_new(struct master **out);
static void master_free(struct master *m);
static int master_run(struct master *m);
static int master_poll(struct master *m);
static int master_handle_stdin(struct master *m);
static int master_handle_signal(struct master *m);
static int master_handle_bus(struct master *m);
static int master_reply(struct master *m, const struct kdbus_msg *msg);
static int master_waitpid(struct master *m);
static int master_spawn(struct master *m);

struct child {
	struct bus *bus;
	struct prime *prime;
};

static int child_new(struct child **out, struct prime *p);
static void child_free(struct child *c);
static int child_run(struct child *c);

/* END OF FORWARD DECLARATIONS */

/*
 * This is the main entrypoint of this example. It is pretty straightforward. We
 * create a master object, run the computation, print a status report and then
 * exit. Nothing particularly interesting here, so lets look into the master
 * object...
 */
int main(int argc, char **argv)
{
	struct master *m = NULL;
	int r;

	r = master_new(&m);
	if (r < 0)
		goto out;

	r = master_run(m);
	if (r < 0)
		goto out;

	if (0)
		prime_print(m->prime);

out:
	master_free(m);
	if (r < 0 && r != -EINTR)
		fprintf(stderr, "failed\n");
	else
		fprintf(stderr, "done\n");
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * ...this will allocate a new master context. It keeps track of the current
 * number of children/workers that are running, manages a signalfd to track
 * SIGCHLD, and creates a private kdbus bus. Afterwards, it opens its connection
 * to the bus and acquires a well known-name (arg_busname).
 */
static int master_new(struct master **out)
{
	struct master *m;
	sigset_t smask;
	int r;

	m = calloc(1, sizeof(*m));
	if (!m)
		return err("cannot allocate master");

	m->max_workers = WORKER_COUNT;
	m->signal_fd = -1;
	m->control_fd = -1;

	sigemptyset(&smask);
	sigaddset(&smask, SIGINT);
	sigaddset(&smask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &smask, NULL);

	m->signal_fd = signalfd(-1, &smask, SFD_CLOEXEC);
	if (m->signal_fd < 0) {
		r = err("cannot create signalfd");
		goto error;
	}

	r = prime_new(&m->prime);
	if (r < 0)
		goto error;

	m->control_fd = bus_make(getuid(), arg_busname);
	if (m->control_fd < 0) {
		r = m->control_fd;
		goto error;
	}

	r = bus_open(&m->bus, getuid(), arg_busname, KDBUS_ATTACH_PIDS);
	if (r < 0)
		goto error;

	r = bus_acquire(m->bus, arg_master);
	if (r < 0)
		goto error;

	*out = m;
	return 0;

error:
	master_free(m);
	return r;
}

/* pretty straightforward destructor of a master object */
static void master_free(struct master *m)
{
	if (!m)
		return;

	bus_close(m->bus);
	if (m->control_fd >= 0)
		close(m->control_fd);
	prime_free(m->prime);
	if (m->signal_fd >= 0)
		close(m->signal_fd);
	free(m);
}

static int master_run(struct master *m)
{
	int res, r = 0;

	while (!prime_done(m->prime)) {
		while (m->n_workers < m->max_workers) {
			r = master_spawn(m);
			if (r < 0)
				break;
		}

		r = master_poll(m);
		if (r < 0)
			break;
	}

	if (r < 0) {
		bus_close(m->bus);
		m->bus = NULL;
	}

	while (m->n_workers > 0) {
		res = master_poll(m);
		if (res < 0) {
			if (m->bus) {
				bus_close(m->bus);
				m->bus = NULL;
			}
			r = res;
		}
	}

	return r == -EINTR ? 0 : r;
}

static int master_poll(struct master *m)
{
	struct pollfd fds[3] = {};
	int r = 0, n = 0;

	fds[n].fd = STDIN_FILENO;
	fds[n++].events = POLLIN;
	fds[n].fd = m->signal_fd;
	fds[n++].events = POLLIN;
	if (m->bus) {
		fds[n].fd = m->bus->fd;
		fds[n++].events = POLLIN;
	}

	r = poll(fds, n, -1);
	if (r < 0)
		return err("poll() failed");

	if (fds[0].revents & POLLIN)
		r = master_handle_stdin(m);
	else if (fds[0].revents)
		r = err("ERR/HUP on stdin");
	if (r < 0)
		return r;

	if (fds[1].revents & POLLIN)
		r = master_handle_signal(m);
	else if (fds[1].revents)
		r = err("ERR/HUP on signalfd");
	if (r < 0)
		return r;

	if (fds[2].revents & POLLIN)
		r = master_handle_bus(m);
	else if (fds[2].revents)
		r = err("ERR/HUP on bus");

	return r;
}

static int master_handle_stdin(struct master *m)
{
	char buf[128];
	ssize_t l;
	int r = 0;

	l = read(STDIN_FILENO, buf, sizeof(buf));
	if (l < 0)
		return err("cannot read stdin");
	if (l == 0)
		return err_r(-EINVAL, "EOF on stdin");

	while (l-- > 0) {
		switch (buf[l]) {
		case 'q':
			/* quit */
			r = -EINTR;
			break;
		case '\n':
		case ' ':
			/* ignore */
			break;
		default:
			if (isgraph(buf[l]))
				fprintf(stderr, "invalid input '%c'\n", buf[l]);
			else
				fprintf(stderr, "invalid input 0x%x\n", buf[l]);
			break;
		}
	}

	return r;
}

static int master_handle_signal(struct master *m)
{
	struct signalfd_siginfo val;
	ssize_t l;

	l = read(m->signal_fd, &val, sizeof(val));
	if (l < 0)
		return err("cannot read signalfd");
	if (l != sizeof(val))
		return err_r(-EINVAL, "invalid data from signalfd");

	switch (val.ssi_signo) {
	case SIGCHLD:
		return master_waitpid(m);
	case SIGINT:
		return err_r(-EINTR, "interrupted");
	default:
		return err_r(-EINVAL, "caught invalid signal");
	}
}

static int master_handle_bus(struct master *m)
{
	struct kdbus_cmd_recv recv = { .size = sizeof(recv) };
	const struct kdbus_msg *msg = NULL;
	const struct kdbus_item *item;
	const struct kdbus_vec *vec = NULL;
	int r = 0;

	r = kdbus_cmd_recv(m->bus->fd, &recv);
	if (r == -EAGAIN)
		return 0;
	if (r < 0)
		return err_r(r, "cannot receive message");

	msg = (void *)(m->bus->pool + recv.msg.offset);

	KDBUS_FOREACH(item, msg->items,
		      msg->size - offsetof(struct kdbus_msg, items)) {
		if (item->type == KDBUS_ITEM_PAYLOAD_OFF) {
			if (vec) {
				r = err_r(-EEXIST,
					  "message with multiple vecs");
				break;
			}
			vec = &item->vec;
			if (vec->size != 1) {
				r = err_r(-EINVAL, "invalid message size");
				break;
			}
		} else if (item->type == KDBUS_ITEM_PAYLOAD_MEMFD) {
			r = err_r(-EINVAL, "message with memfd");
			break;
		}
	}
	if (r < 0)
		goto exit;
	if (!vec) {
		r = err_r(-EINVAL, "empty message");
		goto exit;
	}

	switch (*((const uint8_t *)msg + vec->offset)) {
	case 'r': {
		r = master_reply(m, msg);
		break;
	}
	default:
		r = err_r(-EINVAL, "invalid message type");
		break;
	}

exit:
	bus_release(m->bus, (uint8_t *)msg - m->bus->pool);
	return r;
}

static int master_reply(struct master *m, const struct kdbus_msg *msg)
{
	struct kdbus_cmd_send cmd;
	struct kdbus_item *item;
	struct kdbus_msg *reply;
	size_t size, status, p[2];
	int r;

	p[0] = m->prime->done;
	p[1] = prime_done(m->prime) ? 0 : PRIME_STEPS;

	size = sizeof(*reply);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	reply = alloca(size);
	memset(reply, 0, size);
	reply->size = size;
	reply->cookie = 1;
	reply->payload_type = 0xdeadbeef;
	reply->cookie_reply = msg->cookie;
	reply->dst_id = msg->src_id;

	item = reply->items;
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)p;
	item->vec.size = sizeof(p);

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)reply;

	r = kdbus_cmd_send(m->bus->fd, &cmd);
	if (r < 0)
		return err_r(r, "cannot send reply");

	if (p[1]) {
		prime_consume(m->prime, p[1]);
		status = m->prime->done * 10000 / m->prime->max;
		if (status != m->prime->status) {
			m->prime->status = status;
			fprintf(stderr, "status: %7.3lf%%\n",
				(double)status / 100);
		}
	}

	return 0;
}

static int master_waitpid(struct master *m)
{
	pid_t pid;
	int r;

	while ((pid = waitpid(-1, &r, WNOHANG)) > 0) {
		if (m->n_workers > 0)
			--m->n_workers;
		if (!WIFEXITED(r))
			r = err_r(-EINVAL, "child died unexpectedly");
		else if (WEXITSTATUS(r) != 0)
			r = err_r(-WEXITSTATUS(r), "child failed");
	}

	return r;
}

static int master_spawn(struct master *m)
{
	struct child *c = NULL;
	struct prime *p = NULL;
	pid_t pid;
	int r;

	pid = fork();
	if (pid < 0)
		return err("cannot fork");
	if (pid > 0) {
		/* parent */
		++m->n_workers;
		return 0;
	}

	/* child */

	p = m->prime;
	m->prime = NULL;
	master_free(m);

	r = child_new(&c, p);
	if (r < 0)
		goto exit;

	r = child_run(c);

exit:
	child_free(c);
	exit(abs(r));
}

static int child_new(struct child **out, struct prime *p)
{
	struct child *c;
	int r;

	c = calloc(1, sizeof(*c));
	if (!c)
		return err("cannot allocate child");

	c->prime = p;

	r = bus_open(&c->bus, getuid(), arg_busname, KDBUS_ATTACH_NAMES);
	if (r < 0)
		goto error;

	r = bus_install(c->bus, arg_master);
	if (r < 0)
		goto error;

	*out = c;
	return 0;

error:
	child_free(c);
	return r;
}

static void child_free(struct child *c)
{
	if (!c)
		return;

	bus_close(c->bus);
	prime_free(c->prime);
	free(c);
}

static int child_run(struct child *c)
{
	struct kdbus_cmd_send cmd;
	struct kdbus_item *item;
	struct kdbus_vec *vec = NULL;
	struct kdbus_msg *msg;
	struct timespec spec;
	size_t n, steps, size;
	int r = 0;

	size = sizeof(*msg);
	size += KDBUS_ITEM_SIZE(strlen(arg_master) + 1);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	msg = alloca(size);
	memset(msg, 0, size);
	msg->size = size;
	msg->flags = KDBUS_MSG_EXPECT_REPLY;
	msg->cookie = 1;
	msg->payload_type = 0xdeadbeef;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &spec);
	msg->timeout_ns += (5 + spec.tv_sec) * 1000ULL * 1000ULL * 1000ULL;
	msg->timeout_ns += spec.tv_nsec;

	item = msg->items;
	item->type = KDBUS_ITEM_DST_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(arg_master) + 1;
	strcpy(item->str, arg_master);

	item = KDBUS_ITEM_NEXT(item);
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)"r";
	item->vec.size = 1;

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.flags = KDBUS_SEND_SYNC_REPLY;
	cmd.msg_address = (uintptr_t)msg;

	r = kdbus_cmd_send(c->bus->fd, &cmd);
	if (r == -ESRCH || r == -EPIPE || r == -ECONNRESET)
		return 0;
	if (r < 0)
		return err_r(r, "cannot send request to master");

	msg = (void *)(c->bus->pool + cmd.reply.offset);

	KDBUS_FOREACH(item, msg->items,
		      msg->size - offsetof(struct kdbus_msg, items)) {
		if (item->type == KDBUS_ITEM_PAYLOAD_OFF) {
			if (vec) {
				r = err_r(-EEXIST,
					  "message with multiple vecs");
				break;
			}
			vec = &item->vec;
			if (vec->size != 2 * sizeof(size_t)) {
				r = err_r(-EINVAL, "invalid message size");
				break;
			}
		} else if (item->type == KDBUS_ITEM_PAYLOAD_MEMFD) {
			r = err_r(-EINVAL, "message with memfd");
			break;
		}
	}
	if (r < 0)
		goto exit;
	if (!vec) {
		r = err_r(-EINVAL, "empty message");
		goto exit;
	}

	n = ((size_t*)((const uint8_t *)msg + vec->offset))[0];
	steps = ((size_t*)((const uint8_t *)msg + vec->offset))[1];

	while (steps-- > 0) {
		++n;
		r = prime_run(c->prime, c->bus, n);
		if (r < 0)
			break;
		r = bus_poll(c->bus);
		if (r != 0) {
			r = r < 0 ? r : -EINTR;
			break;
		}
	}

exit:
	bus_release(c->bus, (uint8_t *)msg - c->bus->pool);
	return r;
}

/*
 * Prime Computation
 *
 */

static int prime_new(struct prime **out)
{
	struct prime *p;
	int r;

	p = calloc(1, sizeof(*p));
	if (!p)
		return err("cannot allocate prime memory");

	p->fd = -1;
	p->area = MAP_FAILED;
	p->max = MAX_PRIMES;

	p->fd = syscall(__NR_memfd_create, "prime-area", MFD_CLOEXEC);
	if (p->fd < 0) {
		r = err("cannot create memfd");
		goto error;
	}

	r = ftruncate(p->fd, p->max / 8 + 1);
	if (r < 0) {
		r = err("cannot ftruncate area");
		goto error;
	}

	p->area = mmap(NULL, p->max / 8 + 1, PROT_READ | PROT_WRITE,
		       MAP_SHARED, p->fd, 0);
	if (p->area == MAP_FAILED) {
		r = err("cannot mmap memfd");
		goto error;
	}

	*out = p;
	return 0;

error:
	prime_free(p);
	return r;
}

static void prime_free(struct prime *p)
{
	if (!p)
		return;

	if (p->area != MAP_FAILED)
		munmap(p->area, p->max / 8 + 1);
	if (p->fd >= 0)
		close(p->fd);
	free(p);
}

static bool prime_done(struct prime *p)
{
	return p->done >= p->max;
}

static void prime_consume(struct prime *p, size_t amount)
{
	p->done += amount;
}

static int prime_run(struct prime *p, struct bus *cancel, size_t number)
{
	size_t i, n = 0;
	int r;

	if (number < 2 || number > 65535)
		return 0;

	for (i = number * number;
	     i < p->max && i > number;
	     i += number) {
		p->area[i / 8] |= 1 << (i % 8);

		if (!(++n % (1 << 20))) {
			r = bus_poll(cancel);
			if (r != 0)
				return r < 0 ? r : -EINTR;
		}
	}

	return 0;
}

static void prime_print(struct prime *p)
{
	size_t i, l = 0;

	fprintf(stderr, "PRIMES:");
	for (i = 0; i < p->max; ++i) {
		if (!(p->area[i / 8] & (1 << (i % 8))))
			fprintf(stderr, "%c%7zu", !(l++ % 16) ? '\n' : ' ', i);
	}
	fprintf(stderr, "\nEND\n");
}

static int bus_open(struct bus **out, uid_t uid, const char *name,
		    uint64_t recv_flags)
{
	struct kdbus_cmd_hello hello;
	char path[128];
	struct bus *b;
	int r;

	b = calloc(1, sizeof(*b));
	if (!b)
		return err("cannot allocate bus memory");

	b->fd = -1;
	b->pool = MAP_FAILED;

	snprintf(path, sizeof(path), "/sys/fs/%s/%lu-%s/bus",
		 arg_modname, (unsigned long)uid, name);
	b->fd = open(path, O_RDWR | O_CLOEXEC);
	if (b->fd < 0) {
		r = err("cannot open bus");
		goto error;
	}

	memset(&hello, 0, sizeof(hello));
	hello.size = sizeof(hello);
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;
	hello.attach_flags_recv = recv_flags;
	hello.pool_size = POOL_SIZE;
	r = kdbus_cmd_hello(b->fd, &hello);
	if (r < 0) {
		err_r(r, "HELLO failed");
		goto error;
	}

	bus_release(b, hello.offset);

	b->pool = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, b->fd, 0);
	if (b->pool == MAP_FAILED) {
		r = err("cannot mmap pool");
		goto error;
	}

	*out = b;
	return 0;

error:
	bus_close(b);
	return r;
}

static void bus_close(struct bus *b)
{
	if (!b)
		return;

	if (b->pool != MAP_FAILED)
		munmap(b->pool, POOL_SIZE);
	if (b->fd >= 0)
		close(b->fd);
	free(b);
}

static void bus_release(struct bus *b, uint64_t offset)
{
	struct kdbus_cmd_free cmd = {
		.size = sizeof(cmd),
		.offset = offset,
	};
	int r;

	r = kdbus_cmd_free(b->fd, &cmd);
	if (r < 0)
		err_r(r, "cannot free pool slice");
}

static int bus_acquire(struct bus *b, const char *name)
{
	struct kdbus_item *item;
	struct kdbus_cmd *cmd;
	size_t size;
	int r;

	size = sizeof(*cmd);
	size += KDBUS_ITEM_SIZE(strlen(name) + 1);

	cmd = alloca(size);
	memset(cmd, 0, size);
	cmd->size = size;

	item = cmd->items;
	item->type = KDBUS_ITEM_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
	strcpy(item->str, name);

	r = kdbus_cmd_name_acquire(b->fd, cmd);
	if (r < 0)
		return err_r(r, "cannot acquire name");

	return 0;
}

static int bus_install(struct bus *b, const char *name)
{
	struct kdbus_cmd_match *match;
	struct kdbus_item *item;
	size_t size;
	int r;

	size = sizeof(*match);
	size += KDBUS_ITEM_SIZE(sizeof(item->name_change) + strlen(name) + 1);

	match = alloca(size);
	memset(match, 0, size);
	match->size = size;

	item = match->items;
	item->type = KDBUS_ITEM_NAME_REMOVE;
	item->size = KDBUS_ITEM_HEADER_SIZE +
			sizeof(item->name_change) + strlen(name) + 1;
	item->name_change.old_id.id = KDBUS_MATCH_ID_ANY;
	item->name_change.new_id.id = KDBUS_MATCH_ID_ANY;
	strcpy(item->name_change.name, name);

	r = kdbus_cmd_match_add(b->fd, match);
	if (r < 0)
		return err_r(r, "cannot add match");

	return 0;
}

static int bus_poll(struct bus *b)
{
	struct pollfd fds[1]= {};
	int r;

	fds[0].fd = b->fd;
	fds[0].events = POLLIN;
	r = poll(fds, sizeof(fds) / sizeof(*fds), 0);
	if (r < 0)
		return err("cannot poll bus");
	return !!(fds[0].revents & POLLIN);
}

static int bus_make(uid_t uid, const char *name)
{
	struct kdbus_item *item;
	struct kdbus_cmd *make;
	char path[128], busname[128];
	size_t size;
	int r, fd;

	snprintf(path, sizeof(path), "/sys/fs/%s/control", arg_modname);
	snprintf(busname, sizeof(busname), "%lu-%s", (unsigned long)uid, name);

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return err("cannot open control file");

	size = sizeof(*make);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_parameter));
	size += KDBUS_ITEM_SIZE(strlen(busname) + 1);

	make = alloca(size);
	memset(make, 0, size);
	make->size = size;

	item = make->items;
	item->type = KDBUS_ITEM_BLOOM_PARAMETER;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(item->bloom_parameter);
	item->bloom_parameter.size = 8;
	item->bloom_parameter.n_hash = 1;

	item = KDBUS_ITEM_NEXT(item);
	item->type = KDBUS_ITEM_MAKE_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(busname) + 1;
	strcpy(item->str, busname);

	r = kdbus_cmd_bus_make(fd, make);
	if (r < 0) {
		err_r(r, "cannot make bus");
		close(fd);
		return r;
	}

	return fd;
}
