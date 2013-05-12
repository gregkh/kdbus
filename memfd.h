/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_MEMFD_H
#define __KDBUS_MEMFD_H

#include "internal.h"

bool is_kdbus_memfd(const struct file *fp);
bool is_kdbus_memfd_sealed(const struct file *fp);
u64 kdbus_memfd_size(const struct file *fp);
int kdbus_memfd_new(int *fd);
#endif
