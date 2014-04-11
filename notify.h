/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_NOTIFY_H
#define __KDBUS_NOTIFY_H

struct kdbus_bus;

int kdbus_notify_id_change(struct kdbus_bus *bus, u64 type, u64 id, u64 flags);
int kdbus_notify_reply_timeout(struct kdbus_bus *bus, u64 id, u64 cookie);
int kdbus_notify_reply_dead(struct kdbus_bus *bus, u64 id, u64 cookie);
int kdbus_notify_name_change(struct kdbus_bus *bus, u64 type,
			     u64 old_id, u64 new_id,
			     u64 old_flags, u64 new_flags,
			     const char *name);
void kdbus_notify_flush(struct kdbus_bus *bus);
void kdbus_notify_free(struct kdbus_bus *bus);
#endif
