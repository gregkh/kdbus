#ifndef _KDBUS_H_
#define _KDBUS_H_

#if IS_ENABLED(CONFIG_KDBUS)

int is_kdbus_handle(const struct file *file);

#else

static inline int is_kdbus_handle(const struct file *file)
{
	return 0;
};

#endif

#endif /* _KDBUS_H_ */
