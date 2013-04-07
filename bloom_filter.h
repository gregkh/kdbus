#ifndef _BLOOM_H_
#define _BLOOM_H_

struct bloom_filter {
	struct kref		kref;
	struct mutex		lock;
	struct list_head	alg_list;
	unsigned int		bitmap_size;
	unsigned long		bitmap[0];
};

struct bloom_filter *bloom_filter_new(int bit_size);
struct bloom_filter *bloom_filter_ref(struct bloom_filter *filter);
void bloom_filter_unref(struct bloom_filter *filter);

int bloom_filter_add_hash_alg(struct bloom_filter *filter,
			      const char *name);

int bloom_filter_add(struct bloom_filter *filter,
		     const u8 *data, unsigned int size);
int bloom_filter_check(struct bloom_filter *filter,
		       const u8 *data, unsigned int size,
		       bool *result);
void bloom_filter_set(struct bloom_filter *filter,
		      const u8 *bit_data);
void bloom_filter_reset(struct bloom_filter *filter);

#endif /* _BLOOM_H_ */
