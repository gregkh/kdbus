/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_DEFAULTS_H
#define __KDBUS_DEFAULTS_H

#include <linux/kernel.h>

/* maximum size of message header and items */
#define KDBUS_MSG_MAX_SIZE		SZ_8K

/* maximum number of message items */
#define KDBUS_MSG_MAX_ITEMS		128

/* maximum number of memfd items per message */
#define KDBUS_MSG_MAX_MEMFD_ITEMS	16

/* max size of ioctl command data */
#define KDBUS_CMD_MAX_SIZE		SZ_32K

/* maximum number of inflight fds in a target queue per user */
#define KDBUS_CONN_MAX_FDS_PER_USER	16

/* maximum message payload size */
#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE		SZ_2M

/* maximum size of bloom bit field in bytes */
#define KDBUS_BUS_BLOOM_MAX_SIZE		SZ_4K

/* maximum length of well-known bus name */
#define KDBUS_NAME_MAX_LEN			255

/* maximum length of bus, domain, ep name */
#define KDBUS_SYSNAME_MAX_LEN			63

/* maximum number of matches per connection */
#define KDBUS_MATCH_MAX				256

/* maximum number of queued messages from the same individual user */
#define KDBUS_CONN_MAX_MSGS			256

/* maximum number of well-known names per connection */
#define KDBUS_CONN_MAX_NAMES			256

/* maximum number of queued requests waiting for a reply */
#define KDBUS_CONN_MAX_REQUESTS_PENDING		128

/* maximum number of connections per user in one domain */
#define KDBUS_USER_MAX_CONN			1024

/* maximum number of buses per user in one domain */
#define KDBUS_USER_MAX_BUSES			16

#endif
