/*
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Linux Foundation
 *
 * Bloom filter implementation.
 * See https://en.wikipedia.org/wiki/Bloom_filter
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
#include <crypto/algapi.h>

#include "bloom_filter.h"

struct bloom_crypto_alg {
	u8			*data;
	unsigned int		len;
	int			hash_tfm_allocated:1;
	struct crypto_hash	*hash_tfm;
	struct list_head	entry;
};

struct bloom_filter *bloom_filter_new(int bit_size)
{
	struct bloom_filter *filter;
	unsigned long bitmap_size = BITS_TO_LONGS(bit_size)
				  * sizeof(unsigned long);

	filter = kzalloc(sizeof(*filter) + bitmap_size, GFP_KERNEL);
	if (!filter)
		return ERR_PTR(-ENOMEM);

	kref_init(&filter->kref);
	mutex_init(&filter->lock);
	filter->bitmap_size = bit_size;
	INIT_LIST_HEAD(&filter->alg_list);

	return filter;
}

struct bloom_filter *bloom_filter_ref(struct bloom_filter *filter)
{
	kref_get(&filter->kref);
	return filter;
}

static void bloom_crypto_alg_free(struct bloom_crypto_alg *alg)
{
	if (alg->hash_tfm_allocated)
		crypto_free_hash(alg->hash_tfm);
	list_del(&alg->entry);
	kfree(alg->data);
	kfree(alg);
}

static void __bloom_filter_free(struct kref *kref)
{
	struct bloom_crypto_alg *alg, *tmp;
	struct bloom_filter *filter =
		container_of(kref, struct bloom_filter, kref);

	mutex_lock(&filter->lock);
	list_for_each_entry_safe(alg, tmp, &filter->alg_list, entry)
		bloom_crypto_alg_free(alg);
	mutex_unlock(&filter->lock);

	kfree(filter);
}

void bloom_filter_unref(struct bloom_filter *filter)
{
	kref_put(&filter->kref, __bloom_filter_free);
}

int bloom_filter_add_crypto_hash(struct bloom_filter *filter,
				 struct crypto_hash *hash_tfm)
{
	struct bloom_crypto_alg *alg;
	int ret = 0;

	alg = kzalloc(sizeof(*alg), GFP_KERNEL);
	if (!alg) {
		ret = -ENOMEM;
		goto exit;
	}

	alg->len = crypto_hash_digestsize(hash_tfm);
	alg->data = kzalloc(alg->len, GFP_KERNEL);
	if (!alg->data) {
		ret = -ENOMEM;
		goto exit_free_alg;
	}

	mutex_lock(&filter->lock);
	list_add_tail(&alg->entry, &filter->alg_list);
	mutex_unlock(&filter->lock);

	return 0;

exit_free_alg:
	kfree(alg);

exit:
	return ret;
}

int bloom_filter_add_hash_alg(struct bloom_filter *filter,
			      const char *name)
{
	struct bloom_crypto_alg *alg;
	int ret = 0;

	alg = kzalloc(sizeof(*alg), GFP_KERNEL);
	if (!alg) {
		ret = -ENOMEM;
		goto exit;
	}

	alg->hash_tfm = crypto_alloc_hash(name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(alg->hash_tfm)) {
		ret = PTR_ERR(alg->hash_tfm);
		goto exit_free_alg;
	}

	alg->hash_tfm_allocated = true;
	alg->len = crypto_hash_digestsize(alg->hash_tfm);
	alg->data = kzalloc(alg->len, GFP_KERNEL);
	if (!alg->data) {
		ret = -ENOMEM;
		goto exit_free_hash;
	}

	mutex_lock(&filter->lock);
	list_add_tail(&alg->entry, &filter->alg_list);
	mutex_unlock(&filter->lock);

	return 0;

exit_free_hash:
	crypto_free_hash(alg->hash_tfm);

exit_free_alg:
	kfree(alg);

exit:
	return ret;
}

int __bit_for_crypto_alg(struct bloom_crypto_alg *alg,
			 struct scatterlist *sg,
			 unsigned int wrap_size,
			 unsigned int *bit)
{
	struct hash_desc desc;
	unsigned int i;
	int ret;

	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	desc.tfm = alg->hash_tfm;

	ret = crypto_hash_init(&desc);
	if (ret < 0)
		return ret;

	ret = crypto_hash_digest(&desc, sg, sg->length, alg->data);
	if (ret < 0)
		return ret;

	*bit = 0;

	for (i = 0; i < alg->len; i++) {
		*bit += alg->data[i];
		*bit %= wrap_size;
	}

	return 0;
}

int bloom_filter_add(struct bloom_filter *filter,
		     const u8 *data, unsigned int size)
{
	struct bloom_crypto_alg *alg;
	struct scatterlist sg;
	int ret = 0;

	mutex_lock(&filter->lock);
	if (list_empty(&filter->alg_list)) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	sg_init_one(&sg, data, size);

	list_for_each_entry(alg, &filter->alg_list, entry) {
		unsigned int bit;

		ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
		if (ret < 0)
			goto exit_unlock;

		set_bit(bit, filter->bitmap);
	}

exit_unlock:
	mutex_unlock(&filter->lock);

	return ret;
}

int bloom_filter_check(struct bloom_filter *filter,
		       const u8 *data, unsigned int size,
		       bool *result)
{
	struct bloom_crypto_alg *alg;
	struct scatterlist sg;
	int ret = 0;

	mutex_lock(&filter->lock);
	if (list_empty(&filter->alg_list)) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	sg_init_one(&sg, data, size);

	*result = true;

	list_for_each_entry(alg, &filter->alg_list, entry) {
		unsigned int bit;

		ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
		if (ret < 0)
			goto exit_unlock;

		if (!test_bit(bit, filter->bitmap)) {
			*result = false;
			break;
		}
	}

exit_unlock:
	mutex_unlock(&filter->lock);

	return ret;
}

void bloom_filter_set(struct bloom_filter *filter,
		      const u8 *bit_data)
{
	memcpy(filter->bitmap, bit_data,
		BITS_TO_LONGS(filter->bitmap_size) * sizeof(unsigned long));
}

void bloom_filter_reset(struct bloom_filter *filter)
{
	mutex_lock(&filter->lock);
	bitmap_zero(filter->bitmap, filter->bitmap_size);
	mutex_unlock(&filter->lock);
}

