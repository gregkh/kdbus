/*
 * Copyright (C) 2013-2014 Kay Sievers
 * Copyright (C) 2013-2014 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2014 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2014 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2014 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_DEFAULTS_H
#define __KDBUS_DEFAULTS_H

/* maximum size of message header and items */
#define KDBUS_MSG_MAX_SIZE		SZ_8K

/* maximum number of message items */
#define KDBUS_MSG_MAX_ITEMS		128

/*
 * Maximum number of passed file descriptors
 * Number taken from AF_UNIX upper limits
 */
#define KDBUS_MSG_MAX_FDS		253

/* maximum message payload size */
#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE		SZ_2M

/* maximum size of bloom bit field in bytes */
#define KDBUS_BUS_BLOOM_MAX_SIZE		SZ_4K

/* maximum length of well-known bus name */
#define KDBUS_NAME_MAX_LEN			255

/* maximum length of bus, domain, ep name */
#define KDBUS_SYSNAME_MAX_LEN			63

/* maximum size of make data */
#define KDBUS_MAKE_MAX_SIZE			SZ_32K

/* maximum size of hello data */
#define KDBUS_HELLO_MAX_SIZE			SZ_32K

/* maximum size for update commands */
#define KDBUS_UPDATE_MAX_SIZE			SZ_32K

/* maximum number of matches per connection */
#define KDBUS_MATCH_MAX				256

/* maximum size of match data */
#define KDBUS_MATCH_MAX_SIZE			SZ_32K

/* maximum size of policy data */
#define KDBUS_POLICY_MAX_SIZE			SZ_32K

/* maximum number of queued messages in a connection */
#define KDBUS_CONN_MAX_MSGS			256

/* maximum number of queued messages from the same indvidual user */
#define KDBUS_CONN_MAX_MSGS_PER_USER		16

/* maximum number of well-known names per connection */
#define KDBUS_CONN_MAX_NAMES			64

/* maximum number of queued requests waiting for a reply */
#define KDBUS_CONN_MAX_REQUESTS_PENDING		128

/* maximum number of connections per user in one domain */
#define KDBUS_USER_MAX_CONN			256

/* maximum number of buses per user in one domain */
#define KDBUS_USER_MAX_BUSES			16

#endif
