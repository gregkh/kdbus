/* userspace api for portal.c */

#ifndef _PORTAL_H
#define _PORTAL_H

#include <linux/types.h>

/* Public stuff */
struct umsg {
	__u32	dst_id;
	__u32	size;
	char	data[0];
};

#define PORTAL_IOC_MAGIC 0x96

enum portal_cmd {
	PORTAL_MSG_SEND =	_IOWR(PORTAL_IOC_MAGIC, 0x80, struct umsg),
	PORTAL_MSG_RECV =	_IOWR(PORTAL_IOC_MAGIC, 0x81, struct umsg),
};

/* End public stuff */

#endif
