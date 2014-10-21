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

#ifndef __KDBUS_HANDLE_H
#define __KDBUS_HANDLE_H

struct kdbus_domain;
struct kdbus_ep;

extern const struct file_operations kdbus_handle_ops;

enum kdbus_minor_type {
	KDBUS_MINOR_CONTROL,
	KDBUS_MINOR_EP,
	KDBUS_MINOR_CNT
};

int kdbus_minor_init(void);
void kdbus_minor_exit(void);
int kdbus_minor_alloc(enum kdbus_minor_type type, void *ptr, dev_t *out);
void kdbus_minor_free(dev_t devt);
void kdbus_minor_set(dev_t devt, enum kdbus_minor_type type, void *ptr);

/* type-safe kdbus_minor_set() */
static inline void kdbus_minor_set_control(dev_t devt, struct kdbus_domain *d)
{
	kdbus_minor_set(devt, KDBUS_MINOR_CONTROL, d);
}

/* type-safe kdbus_minor_set() */
static inline void kdbus_minor_set_ep(dev_t devt, struct kdbus_ep *e)
{
	kdbus_minor_set(devt, KDBUS_MINOR_EP, e);
}

#endif
