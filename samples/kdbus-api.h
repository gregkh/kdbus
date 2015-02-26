#ifndef KDBUS_API_H
#define KDBUS_API_H

#include <sys/ioctl.h>
#include "../kdbus.h"

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)
#define KDBUS_ITEM_NEXT(item) \
	(typeof(item))(((uint8_t *)item) + KDBUS_ALIGN8((item)->size))
#define KDBUS_FOREACH(iter, first, _size)				\
	for (iter = (first);						\
	     ((uint8_t *)(iter) < (uint8_t *)(first) + (_size)) &&	\
	       ((uint8_t *)(iter) >= (uint8_t *)(first));		\
	     iter = (void*)(((uint8_t *)iter) + KDBUS_ALIGN8((iter)->size)))

static inline int kdbus_cmd_bus_make(int control_fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(control_fd, KDBUS_CMD_BUS_MAKE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_endpoint_make(int bus_fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(bus_fd, KDBUS_CMD_ENDPOINT_MAKE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_endpoint_update(int ep_fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(ep_fd, KDBUS_CMD_ENDPOINT_UPDATE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_hello(int bus_fd, struct kdbus_cmd_hello *cmd)
{
	int ret = ioctl(bus_fd, KDBUS_CMD_HELLO, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_update(int fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(fd, KDBUS_CMD_UPDATE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_byebye(int conn_fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_BYEBYE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_free(int conn_fd, struct kdbus_cmd_free *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_FREE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_conn_info(int conn_fd, struct kdbus_cmd_info *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_CONN_INFO, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_bus_creator_info(int conn_fd, struct kdbus_cmd_info *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_BUS_CREATOR_INFO, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_list(int fd, struct kdbus_cmd_list *cmd)
{
	int ret = ioctl(fd, KDBUS_CMD_LIST, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_send(int conn_fd, struct kdbus_cmd_send *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_SEND, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_recv(int conn_fd, struct kdbus_cmd_recv *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_RECV, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_name_acquire(int conn_fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_NAME_ACQUIRE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_name_release(int conn_fd, struct kdbus_cmd *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_NAME_RELEASE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_match_add(int conn_fd, struct kdbus_cmd_match *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_MATCH_ADD, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

static inline int kdbus_cmd_match_remove(int conn_fd, struct kdbus_cmd_match *cmd)
{
	int ret = ioctl(conn_fd, KDBUS_CMD_MATCH_REMOVE, cmd);
	return (ret < 0) ? (errno > 0 ? -errno : -EINVAL) : 0;
}

#endif /* KDBUS_API_H */
