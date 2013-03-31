/*
 * kdbus - interprocess message routing
 *
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/hash.h>
//#include <uapi/linux/major.h>
#include "kdbus.h"

#include "kdbus_internal.h"

#define KDBUS_MSG_DATA_SIZE(SIZE) \
	ALIGN((SIZE) + offsetof(struct kdbus_msg_data, data), sizeof(u64))

static void __kdbus_name_registry_free(struct kref *kref)
{
	struct kdbus_name_registry *reg =
		container_of(kref, struct kdbus_name_registry, kref);
	kfree(reg);
}

void kdbus_name_registry_unref(struct kdbus_name_registry *reg)
{
	kref_put(&reg->kref, __kdbus_name_registry_free);
}

struct kdbus_name_registry *kdbus_name_registry_new(void)
{
	struct kdbus_name_registry *reg;

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (!reg)
		return NULL;

	kref_init(&reg->kref);
	INIT_LIST_HEAD(&reg->entries_list);
	mutex_init(&reg->entries_lock);

	return reg;
}

static u64 kdbus_name_make_hash(const char *name)
{
	unsigned int len = strlen(name);
	u64 hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(*name++, hash);

	return end_name_hash(hash);
}

struct kdbus_name_entry *__kdbus_name_lookup(struct kdbus_name_registry *reg,
					     u64 hash, const char *name,
					     u64 type)
{
	struct kdbus_name_entry *tmp, *e;

	list_for_each_entry_safe(e, tmp, &reg->entries_list, list) {
		if (e->hash == hash && e->type == type &&
		    strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

static void kdbus_name_entry_free(struct kdbus_name_entry *e)
{
	kfree(e->name);
	kfree(e);
}

int kdbus_name_add(struct kdbus_name_registry *reg,
		   const char *name, u64 type)
{
	u64 hash = kdbus_name_make_hash(name);
	struct kdbus_name_entry *e;
	int ret = 0;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->name = kstrdup(name, GFP_KERNEL);
	if (!e->name)
		return -ENOMEM;

	e->hash = kdbus_name_make_hash(name);
	e->type = type;
	INIT_LIST_HEAD(&e->list);

	mutex_lock(&reg->entries_lock);
	if (__kdbus_name_lookup(reg, hash, name, type) != NULL)
		ret = -EEXIST;
	else
		list_add_tail(&reg->entries_list, &e->list);
	mutex_unlock(&reg->entries_lock);

	if (ret < 0)
		kdbus_name_entry_free(e);

	return ret;
}

struct kdbus_name_entry *kdbus_name_lookup(struct kdbus_name_registry *reg,
					   const char *name, u64 type)
{
	struct kdbus_name_entry *e = NULL;
	u64 hash = kdbus_name_make_hash(name);

	mutex_lock(&reg->entries_lock);
	e = __kdbus_name_lookup(reg, hash, name, type);
	mutex_unlock(&reg->entries_lock);

	return e;
}

