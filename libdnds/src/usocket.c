/*
 * usocket.c: UNIX domain socket API
 * Copyright 2012. The OpenDNDS team. <team@opendnds.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "event.h"
#include "ion.h"
#include "journal.h"
#include "usocket.h"
#include "xsched.h"

static int (*usocket_context_handler[Q_COUNT])(usocket_t *, int);

static inline void register_context_handler(
			int (**hlist)(usocket_t *, int),
			int (*handler)(usocket_t *, int),
			enum usocket_context_handler index)
{
	hlist[index] = handler;
}

int usocket_close(usocket_t *su)
{
	assert(su);

	if (su->buf) {
		fclose(su->buf);
	} else {
		close(su->fd);
	}

	free(su);
	return 0;
}

static int usocket_remote_recv(usocket_t *su)
{
	assert(su);
	if (su->handler && su->handler->recv) {
		su->handler->recv(su);
		return 0;
	}
	return -1;
}

static int usocket_remote_close(usocket_t *su)
{
	char buf;
	int ret;

	assert(su);

	ret = recv(su->fd, &buf, 1, MSG_DONTWAIT);
	if (!ret) {
		JOURNAL_DEBUG("usocket]> orderly shutdown request on socket "
		    "%i :: %s:%i", su->fd, __FILE__, __LINE__);
	} else if (ret < 0) {
		JOURNAL_DEBUG("usocket]> socket %i failure: %s :: %s:%i",
		    su->fd, strerror(errno), __FILE__, __LINE__);
	}

	if (su->handler && su->handler->close) {
		su->handler->close(su);
	} else {
		JOURNAL_DEBUG("usocket]> no close() handler for socket "
		    "%i :: %s:%i", su->fd, __FILE__, __LINE__);
	}

	return ret;
}

static int usocket_remote_handler(usocket_t *su, int flag)
{
	int ret = -1;
	switch (flag) {
		case ION_READ:
			ret = usocket_remote_recv(su);
			break;
		case ION_EROR:
			ret = usocket_remote_close(su);
			if (!ret)
				/* The remote hung up gently */
				break;

			/* No break here */
		default:
			JOURNAL_DEBUG("usocket]> error in %s, flag=0x%02x :: "
			    "%s:%i", __func__, flag, __FILE__, __LINE__);
			break;
	}
	return ret;
}

static int usocket_remote_accept(usocket_t *su)
{
	int sunaddr_len;
	struct sockaddr_un sunaddr;
	usocket_t *remote;

	remote = calloc(1, sizeof(usocket_t));
	if (remote == NULL) {
		JOURNAL_DEBUG("usocket]> calloc() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	sunaddr_len = sizeof(struct sockaddr_un);
	remote->fd = accept(su->fd, (struct sockaddr *)&sunaddr, &sunaddr_len);
	if (remote->fd < 0) {
			JOURNAL_DEBUG("usocket]> accept() failed: %s :: %s:%i",
			    strerror(errno), __FILE__, __LINE__);
		free(remote);
		return -1;
	}
	JOURNAL_DEBUG("usocket]> accepting connection on socket %i :: %s:%i",
	    remote->fd, __FILE__, __LINE__);

	remote->buf = fdopen(remote->fd, "r+");
	if (remote->buf == NULL) {
		JOURNAL_DEBUG("usocket]> fdopen() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(remote);
		return -1;
	}

	remote->context = Q_REMOTE;

	usocket_register_handler(remote, su->handler);

	if (usocket_queue_add(su->queue, remote, su->udata)) {
		JOURNAL_DEBUG("usocket]> usocket_queue_add() failed :: %s:%i",
			__FILE__, __LINE__);
		usocket_close(remote);
		return -1;
	}

	return 0;
}

static int usocket_listener_handler(usocket_t *su, int flag)
{
	int ret = -1;
	switch (flag) {
		case ION_READ:
			ret = usocket_remote_accept(su);
			break;
		default:
		case ION_EROR:
			JOURNAL_DEBUG("usocket]> error in %s, flag=0x%02x :: "
			    "%s:%i", __func__, flag, __FILE__, __LINE__);
			break;
	}
	return ret;
}

static void usocket_dispatch(void *udata, int flag)
{
	usocket_t *su = udata;

	assert(su);

	int (*context_handler)(usocket_t *, int) =
	    usocket_context_handler[su->context];

	if (context_handler(su, flag) < 0)
		JOURNAL_DEBUG("usocket]> context_handler failed :: %s:%i",
		    __FILE__, __LINE__);
}

static void usocket_poke(void *udata)
{
	int *queue = udata;
	assert(udata != NULL);
	if (ion_poke(*queue, usocket_dispatch) < 0)
		JOURNAL_DEBUG("usocket]> ion_poke() failure on queue %i: "
		    "%s :: %s:%i", queue, strerror(errno), __FILE__, __LINE__);
}

static usocket_t *factory(const char *sun_path, struct sockaddr_un *sunaddr)
{
	usocket_t *su = NULL;

	su = calloc(1, sizeof(usocket_t));
	if (su == NULL) {
		JOURNAL_DEBUG("usocket]> calloc() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	su->fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (su->fd < 0) {
		JOURNAL_DEBUG("usocket]> socket() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	su->buf = fdopen(su->fd, "r+");
	if (su->buf == NULL) {
		JOURNAL_DEBUG("usocket]> fdopen() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(su);
		return NULL;
	}

	memset(sunaddr, 0, sizeof(struct sockaddr_un));
	sunaddr->sun_family = AF_LOCAL;
	strncpy(sunaddr->sun_path, sun_path, sizeof(sunaddr->sun_path));

	return su;
}

int usocket_queue_init(int *queue)
{
	*queue = ion_new();
	if (*queue < 0) {
		JOURNAL_DEBUG("usocket]> ion_new() failed :: %s:%i",
		    __FILE__, __LINE__);
		return -1;
	}

	sched_register(SCHED_APERIODIC, "usocket_poke", usocket_poke, 0, queue);
	return 0;
}

int usocket_queue_add(int queue, usocket_t *su, void *udata)
{
	assert(su);

	su->queue = queue;
	su->udata = udata;

	if (ion_add(queue, su->fd, su)) {
		JOURNAL_DEBUG("usocket]> ion_add() failed :: %s:%i",
		    __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

int usocket_listen(usocket_t *su, int backlog)
{
	assert(su);

	if (listen(su->fd, backlog) < 0) {
		JOURNAL_DEBUG("usocket]> listen() failure: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	su->context = Q_LISTENER;
	return 0;
}

usocket_t *usocket_create(char *sun_path)
{
	usocket_t *su = NULL;
	struct sockaddr_un sunaddr;

	su = factory(sun_path, &sunaddr);
	if (su == NULL) {
		JOURNAL_DEBUG("usocket]> su is NULL :: %s:%i",
		    __FILE__, __LINE__);
		return NULL;
	}

	unlink(sun_path);
	if (bind(su->fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr))) {
		JOURNAL_DEBUG("usocket]> bind() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(su);
		return NULL;
	}

	return su;
}

usocket_t *usocket_connect(char *sun_path)
{
	usocket_t *su = NULL;
	struct sockaddr_un sunaddr;

	su = factory(sun_path, &sunaddr);
	if (su == NULL) {
		JOURNAL_DEBUG("usocket]> su is NULL :: %s:%i",
		    __FILE__, __LINE__);
		return NULL;
	}

	if (connect(su->fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr))) {
		JOURNAL_DEBUG("usocket]> connect() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(su);
		return NULL;
	}
	su->context = Q_REMOTE;

	return su;
}

int usocket_init()
{
	register_context_handler(usocket_context_handler,
			usocket_listener_handler, Q_LISTENER);

	register_context_handler(usocket_context_handler,
			usocket_remote_handler, Q_REMOTE);

	return 0;
}
