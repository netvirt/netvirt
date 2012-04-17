/*
 * usocket.h: UNIX domain socket API
 * Copyright 2012. The OpenDNDS team. <team@opendnds.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#ifndef DNDS_SOCKET_H
#define DNDS_SOCKET_H

#include <stdio.h>

enum usocket_context_handler {
	Q_LISTENER = 0,
	Q_REMOTE,
	Q_COUNT		/* always last element */
};

typedef struct usocket usocket_t;
typedef struct {
	void (*recv)(usocket_t *);
	void (*close)(usocket_t *);
} usocket_handler_t;

struct usocket {
	int fd;
	int queue;
	FILE *buf;
	enum usocket_context_handler context;
	usocket_handler_t *handler;
	void *udata;
};

static inline void usocket_register_handler(usocket_t *s, usocket_handler_t *h)
{
	s->handler = h;
}

int usocket_init();
usocket_t *usocket_create(char *);
usocket_t *usocket_connect(char *);
int usocket_listen(usocket_t *, int);
int usocket_queue_init(int *);
int usocket_queue_add(int, usocket_t *, void *);
int usocket_close(usocket_t *);

#endif /* DNDS_SOCKET_H */
