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
 *  * child:  The child object contains the context of a worker. It inherits the
 *            prime context from its parent (the master) and then creates a new
 *            bus context to request prime-ranges to compute.
 *  * prime:  The "prime" object is used to abstract how we compute primes. When
 *            allocated, it prepares a memory region to hold 1 bit for each
 *            natural number up to a fixed maximum ('MAX_PRIMES').
 *            The memory region is backed by a memfd which we share between
 *            processes. Each worker now gets assigned a range of natural
 *            numbers which it clears multiples of off the memory region. The
 *            master process is responsible of distributing all natural numbers
 *            up to the fixed maximum to its workers.
 *  * bus:    The bus object is an abstraction of the kdbus API. It is pretty
 *            straightfoward and only manages the connection-fd plus the
 *            memory-mapped pool in a single object.
 *
 * This example is in reversed order, which should make it easier to read
 * top-down, but requires some forward-declarations. Just ignore those.
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

static int bus_open_connection(struct bus **out, uid_t uid, const char *name,
			       uint64_t recv_flags);
static void bus_close_connection(struct bus *b);
static void bus_poool_free_slice(struct bus *b, uint64_t offset);
static int bus_acquire_name(struct bus *b, const char *name);
static int bus_install_name_loss_match(struct bus *b, const char *name);
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
 * to the bus and acquires a well known-name (arg_master).
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

	/* Block SIGINT and SIGCHLD signals */
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

	/*
	 * Open a bus connection for the master, and require each received
	 * message to have a metadata item of type KDBUS_ITEM_PIDS attached.
	 * The current UID is needed to compute the name of the bus node to
	 * connect to.
	 */
	r = bus_open_connection(&m->bus, getuid(),
				arg_busname, KDBUS_ATTACH_PIDS);
	if (r < 0)
		goto error;

	/*
	 * Acquire a well-known name on the bus, so children can address
	 * messages to the master using KDBUS_DST_ID_NAME as destination-ID
	 * of messages.
	 */
	r = bus_acquire_name(m->bus, arg_master);
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

	bus_close_connection(m->bus);
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
		bus_close_connection(m->bus);
		m->bus = NULL;
	}

	while (m->n_workers > 0) {
		res = master_poll(m);
		if (res < 0) {
			if (m->bus) {
				bus_close_connection(m->bus);
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

	/*
	 * Add stdin, the eventfd and the connection owner file descriptor to
	 * the pollfd table, and handle incoming traffic on the latter in
	 * master_handle_bus().
	 */
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

	/*
	 * To receive a message, the KDBUS_CMD_RECV ioctl is used.
	 * It takes an argument of type 'struct kdbus_cmd_recv', which
	 * will contain information on the received message when the call
	 * returns. See kdbus.message(7).
	 */
	r = kdbus_cmd_recv(m->bus->fd, &recv);
	/*
	 * EAGAIN is returned when there is no message waiting on this
	 * connection. This is not an error - simply bail out.
	 */
	if (r == -EAGAIN)
		return 0;
	if (r < 0)
		return err_r(r, "cannot receive message");

	/*
	 * Messages received by a connection are stored inside the connection's
	 * pool, at an offset that has been returned in the 'recv' command
	 * struct above. The value describes the relative offset from the
	 * start address of the pool. A message is described with
	 * 'struct kdbus_msg'. See kdbus.message(7).
	 */
	msg = (void *)(m->bus->pool + recv.msg.offset);

	/*
	 * A messages describes its actual payload in an array of items.
	 * KDBUS_FOREACH() is a simple iterator that walks such an array.
	 * struct kdbus_msg has a field to denote its total size, which is
	 * needed to determine the number of items in the array.
	 */
	KDBUS_FOREACH(item, msg->items,
		      msg->size - offsetof(struct kdbus_msg, items)) {
		/*
		 * An item of type PAYLOAD_OFF describes in-line memory
		 * stored in the pool at a described offset. That offset is
		 * relative to the start address of the message header.
		 * This example program only expects one single item of that
		 * type, remembers the struct kdbus_vec member of the item
		 * when it sees it, and bails out if there is more than one
		 * of them.
		 */
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

		/*
		 * MEMFDs are transported as items of type PAYLOAD_MEMFD.
		 * If such an item is attached, a new file descriptor was
		 * installed into the task when KDBUS_CMD_RECV was called, and
		 * its number is stored in item->memfd.fd.
		 * Implementers *must* handle this item type and close the
		 * file descriptor when no longer needed in order to prevent
		 * file descriptor exhaustion. This example program just bails
		 * out with an error in this case, as memfds are not expected
		 * in this context.
		 */
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
	/*
	 * We are done with the memory slice that was given to us through
	 * recv.msg.offset. Tell the kernel it can use it for other content
	 * in the future. See kdbus.pool(7).
	 */
	bus_poool_free_slice(m->bus, recv.msg.offset);
	return r;
}

static int master_reply(struct master *m, const struct kdbus_msg *msg)
{
	struct kdbus_cmd_send cmd;
	struct kdbus_item *item;
	struct kdbus_msg *reply;
	size_t size, status, p[2];
	int r;

	/*
	 * This functions sends a message over kdbus. To do this, it uses the
	 * KDBUS_CMD_SEND ioctl, which takes a command struct argument of type
	 * 'struct kdbus_cmd_send'. This struct stores a pointer to the actual
	 * message to send. See kdbus.message(7).
	 */
	p[0] = m->prime->done;
	p[1] = prime_done(m->prime) ? 0 : PRIME_STEPS;

	size = sizeof(*reply);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	/* Prepare the message to send */
	reply = alloca(size);
	memset(reply, 0, size);
	reply->size = size;

	/* Each message has a cookie that can be used to send replies */
	reply->cookie = 1;

	/* The payload_type is arbitrary, but it must be non-zero */
	reply->payload_type = 0xdeadbeef;

	/*
	 * We are sending a reply. Let the kernel know the cookie of the
	 * message we are replying to.
	 */
	reply->cookie_reply = msg->cookie;

	/*
	 * Messages can either be directed to a well-known name (stored as
	 * string) or to a unique name (stored as number). This example does
	 * the latter. If the message would be directed to a well-known name
	 * instead, the message's dst_id field would be set to
	 * KDBUS_DST_ID_NAME, and the name would be attaches in an item of type
	 * KDBUS_ITEM_DST_NAME. See below for an example, and also refer to
	 * kdbus.message(7).
	 */
	reply->dst_id = msg->src_id;

	/* Our message has exactly one item to store its payload */
	item = reply->items;
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)p;
	item->vec.size = sizeof(p);

	/*
	 * Now prepare the command struct, and reference the message we want
	 * to send.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)reply;

	/*
	 * Finally, employ the command on the connection owner
	 * file descriptor.
	 */
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

	/* Spawn off one child and call child_run() inside it */

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

	/*
	 * Open a connection to the bus and require each received message to
	 * carry a list of the well-known names the sendind connection currently
	 * owns. The current UID is needed in order to determine the name of the
	 * bus node to connect to.
	 */
	r = bus_open_connection(&c->bus, getuid(),
				arg_busname, KDBUS_ATTACH_NAMES);
	if (r < 0)
		goto error;

	/*
	 * Install a kdbus match so the child's connection gets notified when
	 * the master loses its well-known name.
	 */
	r = bus_install_name_loss_match(c->bus, arg_master);
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

	bus_close_connection(c->bus);
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

	/*
	 * Let's send a message to the master and ask for work. To do this,
	 * we use the KDBUS_CMD_SEND ioctl, which takes an argument of type
	 * 'struct kdbus_cmd_send'. This struct stores a pointer to the actual
	 * message to send. See kdbus.message(7).
	 */
	size = sizeof(*msg);
	size += KDBUS_ITEM_SIZE(strlen(arg_master) + 1);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	msg = alloca(size);
	memset(msg, 0, size);
	msg->size = size;

	/*
	 * Tell the kernel that we expect a reply to this message. This means
	 * that
	 *
	 * a) The remote peer will gain temporary permission to talk to us
	 *    even if it would not be allowed to normally.
	 *
	 * b) A timeout value is required.
	 *
	 *    For asynchronous send commands, if no reply is received, we will
	 *    get a kernel notification with an item of type
	 *    KDBUS_ITEM_REPLY_TIMEOUT attached.
	 *
	 *    For synchronous send commands (which this example does), the
	 *    ioctl will block until a reply is received or the timeout is
	 *    exceeded.
	 */
	msg->flags = KDBUS_MSG_EXPECT_REPLY;

	/* Set our cookie. Replies must use this cookie to send their reply. */
	msg->cookie = 1;

	/* The payload_type is arbitrary, but it must be non-zero */
	msg->payload_type = 0xdeadbeef;

	/*
	 * We are sending our message to the current owner of a well-known
	 * name. This makes an item of type KDBUS_ITEM_DST_NAME mandatory.
	 */
	msg->dst_id = KDBUS_DST_ID_NAME;

	/*
	 * Set the reply timeout to 5 seconds. Timeouts are always set in
	 * absolute timestamps, based con CLOCK_MONOTONIC. See kdbus.message(7).
	 */
	clock_gettime(CLOCK_MONOTONIC_COARSE, &spec);
	msg->timeout_ns += (5 + spec.tv_sec) * 1000ULL * 1000ULL * 1000ULL;
	msg->timeout_ns += spec.tv_nsec;

	/*
	 * Fill the appended items. First, set the well-known name of the
	 * destination we want to talk to.
	 */
	item = msg->items;
	item->type = KDBUS_ITEM_DST_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(arg_master) + 1;
	strcpy(item->str, arg_master);

	/*
	 * The 2nd item contains a vector to memory we want to send. It
	 * can be content of any type. In our case, we're sending a one-byte
	 * string only. The memory referenced by this item will be copied into
	 * the pool of the receveiver connection, and does not need to be
	 * valid after the command is employed.
	 */
	item = KDBUS_ITEM_NEXT(item);
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uintptr_t)"r";
	item->vec.size = 1;

	/* Set up the command struct and reference the message we prepared */
	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.msg_address = (uintptr_t)msg;

	/*
	 * The send commands knows a mode in which it will block until a
	 * reply to a message is received. This example uses that mode.
	 * The pool offset to the received reply will be stored in the command
	 * struct after the send command returned. See below.
	 */
	cmd.flags = KDBUS_SEND_SYNC_REPLY;

	/*
	 * Finally, employ the command on the connection owner
	 * file descriptor.
	 */
	r = kdbus_cmd_send(c->bus->fd, &cmd);
	if (r == -ESRCH || r == -EPIPE || r == -ECONNRESET)
		return 0;
	if (r < 0)
		return err_r(r, "cannot send request to master");

	/*
	 * The command was sent with the KDBUS_SEND_SYNC_REPLY flag set,
	 * and returned successfully, which means that cmd.reply.offset now
	 * points to a message inside our connection's pool where the reply
	 * is found. This is equivalent to receiving the reply with
	 * KDBUS_CMD_RECV, but it doesn't require waiting for the reply with
	 * poll() and also saves the ioctl to receive the message.
	 */
	msg = (void *)(c->bus->pool + cmd.reply.offset);

	/*
	 * A messages describes its actual payload in an array of items.
	 * KDBUS_FOREACH() is a simple iterator that walks such an array.
	 * struct kdbus_msg has a field to denote its total size, which is
	 * needed to determine the number of items in the array.
	 */
	KDBUS_FOREACH(item, msg->items,
		      msg->size - offsetof(struct kdbus_msg, items)) {
		/*
		 * An item of type PAYLOAD_OFF describes in-line memory
		 * stored in the pool at a described offset. That offset is
		 * relative to the start address of the message header.
		 * This example program only expects one single item of that
		 * type, remembers the struct kdbus_vec member of the item
		 * when it sees it, and bails out if there is more than one
		 * of them.
		 */
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
		/*
		 * MEMFDs are transported as items of type PAYLOAD_MEMFD.
		 * If such an item is attached, a new file descriptor was
		 * installed into the task when KDBUS_CMD_RECV was called, and
		 * its number is stored in item->memfd.fd.
		 * Implementers *must* handle this item type close the
		 * file descriptor when no longer needed in order to prevent
		 * file descriptor exhaustion. This example program just bails
		 * out with an error in this case, as memfds are not expected
		 * in this context.
		 */
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

	n = ((size_t *)((const uint8_t *)msg + vec->offset))[0];
	steps = ((size_t *)((const uint8_t *)msg + vec->offset))[1];

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
	/*
	 * We are done with the memory slice that was given to us through
	 * cmd.reply.offset. Tell the kernel it can use it for other content
	 * in the future. See kdbus.pool(7).
	 */
	bus_poool_free_slice(c->bus, cmd.reply.offset);
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

	/*
	 * Prepare and map a memfd to store the bit-fields for the number
	 * ranges we want to perform the prime detection on.
	 */
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

static int bus_open_connection(struct bus **out, uid_t uid, const char *name,
			       uint64_t recv_flags)
{
	struct kdbus_cmd_hello hello;
	char path[128];
	struct bus *b;
	int r;

	/*
	 * The 'bus' object is our representation of a kdbus connection which
	 * stores two details: the connection owner file descriptor, and the
	 * mmap()ed memory of its associated pool. See kdbus.connection(7) and
	 * kdbus.pool(7).
	 */
	b = calloc(1, sizeof(*b));
	if (!b)
		return err("cannot allocate bus memory");

	b->fd = -1;
	b->pool = MAP_FAILED;

	/* Compute the name of the bus node to connect to. */
	snprintf(path, sizeof(path), "/sys/fs/%s/%lu-%s/bus",
		 arg_modname, (unsigned long)uid, name);
	b->fd = open(path, O_RDWR | O_CLOEXEC);
	if (b->fd < 0) {
		r = err("cannot open bus");
		goto error;
	}

	/*
	 * To make a connection to the bus, the KDBUS_CMD_HELLO ioctl is used.
	 * It takes an argument of type 'struct kdbus_cmd_hello'.
	 */
	memset(&hello, 0, sizeof(hello));
	hello.size = sizeof(hello);

	/*
	 * Specify a mask of metadata attach flags, describing metadata items
	 * that this new connection allows to be sent.
	 */
	hello.attach_flags_send = _KDBUS_ATTACH_ALL;

	/*
	 * Specify a mask of metadata attach flags, describing metadata items
	 * that this new connection wants to be receive along with each message.
	 */
	hello.attach_flags_recv = recv_flags;

	/*
	 * A connection may choose the size of its pool, but the number has to
	 * comply with two rules: a) it must be greater than 0, and b) it must
	 * be a mulitple of PAGE_SIZE. See kdbus.pool(7).
	 */
	hello.pool_size = POOL_SIZE;

	/*
	 * Now employ the command on the file descriptor opened above.
	 * This command will turn the file descriptor into a connection-owner
	 * file descriptor that controls the life-time of the connection; once
	 * it's closed, the connection is shut down.
	 */
	r = kdbus_cmd_hello(b->fd, &hello);
	if (r < 0) {
		err_r(r, "HELLO failed");
		goto error;
	}

	bus_poool_free_slice(b, hello.offset);

	/*
	 * Map the pool of the connection. Its size has been set in the
	 * command struct above. See kdbus.pool(7).
	 */
	b->pool = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, b->fd, 0);
	if (b->pool == MAP_FAILED) {
		r = err("cannot mmap pool");
		goto error;
	}

	*out = b;
	return 0;

error:
	bus_close_connection(b);
	return r;
}

static void bus_close_connection(struct bus *b)
{
	if (!b)
		return;

	/*
	 * A bus connection is closed by simply calling close() on the
	 * connection owner file descriptor. The unique name and all owned
	 * well-known names of the conneciton will disappear.
	 * See kdbus.connection(7).
	 */
	if (b->pool != MAP_FAILED)
		munmap(b->pool, POOL_SIZE);
	if (b->fd >= 0)
		close(b->fd);
	free(b);
}

static void bus_poool_free_slice(struct bus *b, uint64_t offset)
{
	struct kdbus_cmd_free cmd = {
		.size = sizeof(cmd),
		.offset = offset,
	};
	int r;

	/*
	 * Once we're done with a piece of pool memory that was returned
	 * by a command, we have to call the KDBUS_CMD_FREE ioctl on it so it
	 * can be reused. The command takes an argument of type
	 * 'struct kdbus_cmd_free', in which the pool offset of the slice to
	 * free is stored. The ioctl is employed on the connection owner
	 * file descriptor. See kdbus.pool(7),
	 */
	r = kdbus_cmd_free(b->fd, &cmd);
	if (r < 0)
		err_r(r, "cannot free pool slice");
}

static int bus_acquire_name(struct bus *b, const char *name)
{
	struct kdbus_item *item;
	struct kdbus_cmd *cmd;
	size_t size;
	int r;

	/*
	 * This function acquires a well-known name on the bus through the
	 * KDBUS_CMD_NAME_ACQUIRE ioctl. This ioctl takes an argument of type
	 * 'struct kdbus_cmd', which is assembled below. See kdbus.name(7).
	 */
	size = sizeof(*cmd);
	size += KDBUS_ITEM_SIZE(strlen(name) + 1);

	cmd = alloca(size);
	memset(cmd, 0, size);
	cmd->size = size;

	/*
	 * The command requires an item of type KDBUS_ITEM_NAME, and its
	 * content must be a valid bus name.
	 */
	item = cmd->items;
	item->type = KDBUS_ITEM_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(name) + 1;
	strcpy(item->str, name);

	/*
	 * Employ the command on the connection owner file descriptor.
	 */
	r = kdbus_cmd_name_acquire(b->fd, cmd);
	if (r < 0)
		return err_r(r, "cannot acquire name");

	return 0;
}

static int bus_install_name_loss_match(struct bus *b, const char *name)
{
	struct kdbus_cmd_match *match;
	struct kdbus_item *item;
	size_t size;
	int r;

	/*
	 * In order to install a match for signal messages, we have to
	 * assemble a 'struct kdbus_cmd_match' and use it along with the
	 * KDBUS_CMD_MATCH_ADD ioctl. See kdbus.match(7).
	 */
	size = sizeof(*match);
	size += KDBUS_ITEM_SIZE(sizeof(item->name_change) + strlen(name) + 1);

	match = alloca(size);
	memset(match, 0, size);
	match->size = size;

	/*
	 * A match is comprised of many 'rules', each of which describes a
	 * mandatory detail of the message. All rules of a match must be
	 * satified in order to make a message pass.
	 */
	item = match->items;

	/*
	 * In this case, we're interested in notifications that inform us
	 * about a well-known name being removed from the bus.
	 */
	item->type = KDBUS_ITEM_NAME_REMOVE;
	item->size = KDBUS_ITEM_HEADER_SIZE +
			sizeof(item->name_change) + strlen(name) + 1;

	/*
	 * We could limit the match further and require a specific unique-ID
	 * to be the new or the old owner of the name. In this case, however,
	 * we don't, and allow 'any' id.
	 */
	item->name_change.old_id.id = KDBUS_MATCH_ID_ANY;
	item->name_change.new_id.id = KDBUS_MATCH_ID_ANY;

	/* Copy in the well-known name we're interested in */
	strcpy(item->name_change.name, name);

	/*
	 * Add the match through the KDBUS_CMD_MATCH_ADD ioctl, employed on
	 * the connection owner fd.
	 */
	r = kdbus_cmd_match_add(b->fd, match);
	if (r < 0)
		return err_r(r, "cannot add match");

	return 0;
}

static int bus_poll(struct bus *b)
{
	struct pollfd fds[1] = {};
	int r;

	/*
	 * A connection endpoint supports poll() and will wake-up the
	 * task with POLLIN set once a message has arrived.
	 */
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

	/*
	 * Compute the full path to the 'control' node. 'arg_modname' may be
	 * set to a different value than 'kdbus' for development purposes.
	 * The 'control' node is the primary entry point to kdbus that must be
	 * used in order to create a bus. See kdbus(7) and kdbus.bus(7).
	 */
	snprintf(path, sizeof(path), "/sys/fs/%s/control", arg_modname);

	/*
	 * Compute the bus name. A valid bus name must always be prefixed with
	 * the EUID of the currently running process in order to avoid name
	 * conflicts. See kdbus.bus(7).
	 */
	snprintf(busname, sizeof(busname), "%lu-%s", (unsigned long)uid, name);

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return err("cannot open control file");

	/*
	 * The KDBUS_CMD_BUS_MAKE ioctl takes an argument of type
	 * 'struct kdbus_cmd', and expects at least two items attached to
	 * it: one to decribe the bloom parameters to be propagated to
	 * connections of the bus, and the name of the bus that was computed
	 * above. Assemble this struct now, and fill it with values.
	 */
	size = sizeof(*make);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_parameter));
	size += KDBUS_ITEM_SIZE(strlen(busname) + 1);

	make = alloca(size);
	memset(make, 0, size);
	make->size = size;

	/*
	 * Each item has a 'type' and 'size' field, and must be stored at an
	 * 8-byte aligned address. The KDBUS_ITEM_NEXT macro is used to advance
	 * the pointer. See kdbus.item(7) for more details.
	 */
	item = make->items;
	item->type = KDBUS_ITEM_BLOOM_PARAMETER;
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(item->bloom_parameter);
	item->bloom_parameter.size = 8;
	item->bloom_parameter.n_hash = 1;

	/* The name of the new bus is stored in the next item. */
	item = KDBUS_ITEM_NEXT(item);
	item->type = KDBUS_ITEM_MAKE_NAME;
	item->size = KDBUS_ITEM_HEADER_SIZE + strlen(busname) + 1;
	strcpy(item->str, busname);

	/*
	 * Now create the bus via the KDBUS_CMD_BUS_MAKE ioctl and return the
	 * fd that was used back to the caller of this function. This fd is now
	 * called a 'bus owner file descriptor', and it controls the life-time
	 * of the newly created bus; once the file descriptor is closed, the
	 * bus goes away, and all connections are shut down. See kdbus.bus(7).
	 */
	r = kdbus_cmd_bus_make(fd, make);
	if (r < 0) {
		err_r(r, "cannot make bus");
		close(fd);
		return r;
	}

	return fd;
}
