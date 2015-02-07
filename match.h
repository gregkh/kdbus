/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_MATCH_H
#define __KDBUS_MATCH_H

struct kdbus_conn;
struct kdbus_kmsg;
struct kdbus_match_db;

struct kdbus_match_db *kdbus_match_db_new(void);
void kdbus_match_db_free(struct kdbus_match_db *db);
int kdbus_match_db_add(struct kdbus_conn *conn,
		       struct kdbus_cmd_match *cmd);
int kdbus_match_db_remove(struct kdbus_conn *conn,
			  struct kdbus_cmd_match *cmd);
bool kdbus_match_db_match_kmsg(struct kdbus_match_db *db,
			       struct kdbus_conn *conn_src,
			       struct kdbus_kmsg *kmsg);

int kdbus_cmd_match_add(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_match_remove(struct kdbus_conn *conn, void __user *argp);

#endif
