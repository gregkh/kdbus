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

#ifndef __KDBUS_BUFFER_H
#define __KDBUS_BUFFER_H

/*
 * At KDBUS_CMD_MSG_SEND, messages are placed direcly into the buffer the
 * receiver has registered with KDBUS_HELLO_BUFFER.
 *
 * To receive a message, KDBUS_CMD_MSG_RECV is called, which returns a pointer
 * into the buffer.
 *
 * The internally allocated memory needs to be freed by the receiver with
 * KDBUS_CMD_MSG_RELEASE.
 */
struct kdbus_buffer {
	void __user *buf;	/* receiver-supplied buffer */
	size_t size;		/* size of buffer  */
	size_t pos;		/* current write position */
	unsigned int users;
};

/*
 * Structure to keep the state of a mapped range on the buffer while
 * writing chunks of data to it from the sender.
 */
struct kdbus_buffer_map {
	struct page **pages;	/* array of pages representign the buffer */
	unsigned int n;		/* number pf pages in the array */
	unsigned long cur;	/* current page we write to */
	unsigned long pos;	/* position in current page we write to */
};

struct kdbus_msg __user *kdbus_buffer_alloc(struct kdbus_buffer *buf, size_t len);
void kdbus_buffer_free(struct kdbus_buffer *buf, struct kdbus_msg __user *msg);
void kdbus_buffer_map_close(struct kdbus_buffer_map *map);
int kdbus_buffer_map_open(struct kdbus_buffer_map *map,
			  struct task_struct *task,
			  void __user *to, size_t len);
int kdbus_buffer_map_write(struct kdbus_buffer_map *map,
			   void __user *from, size_t len);
#endif
