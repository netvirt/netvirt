/*
 * usocket.c: UNIX domain socket API
 * Copyright 2012. Jamael Seun
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

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

static int remote_recv(usocket_t *sck)
{
	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	if (sck->handler && sck->handler->recv) {
		sck->handler->recv(sck);
		return 0;
	}

	JOURNAL_DEBUG("usocket]> no recv handler bound to socket :: %s:%i",
	    __FILE__, __LINE__);

	return -1;
}

static int remote_close(usocket_t *sck)
{
	char buf;
	int ret;

	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	ret = recv(sck->fd, &buf, 1, MSG_DONTWAIT);
	if (!ret) {
		JOURNAL_DEBUG("usocket]> orderly shutdown request on socket "
		    "%i :: %s:%i", sck->fd, __FILE__, __LINE__);
	} else if (ret < 0) {
		JOURNAL_DEBUG("usocket]> socket %i failure: %s :: %s:%i",
		    sck->fd, strerror(errno), __FILE__, __LINE__);
	}

	if (sck->handler && sck->handler->close) {
		sck->handler->close(sck);
	} else {
		JOURNAL_DEBUG("usocket]> no close() handler for socket "
		    "%i :: %s:%i", sck->fd, __FILE__, __LINE__);
	}

	return ret;
}

static int remote_handler(usocket_t *sck, int flag)
{
	int ret = -1;

	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	switch (flag) {
		case ION_READ:
			ret = remote_recv(sck);
			break;
		case ION_EROR:
			ret = remote_close(sck);
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

static int remote_accept(usocket_t *sck)
{
	int sunaddr_len;
	struct sockaddr_un sunaddr;
	usocket_t *remote;

	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	remote = calloc(1, sizeof(usocket_t));
	if (remote == NULL) {
		JOURNAL_DEBUG("usocket]> calloc() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	sunaddr_len = sizeof(struct sockaddr_un);
	remote->fd = accept(sck->fd, (struct sockaddr *)&sunaddr, &sunaddr_len);
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

	usocket_register_handler(remote, sck->handler);

	if (usocket_queue_add(sck->queue, remote, sck->udata)) {
		JOURNAL_DEBUG("usocket]> usocket_queue_add() failed :: %s:%i",
			__FILE__, __LINE__);
		usocket_close(remote);
		return -1;
	}

	return 0;
}

static int listener_handler(usocket_t *sck, int flag)
{
	int ret = -1;
	switch (flag) {
		case ION_READ:
			ret = remote_accept(sck);
			break;
		default:
		case ION_EROR:
			JOURNAL_DEBUG("usocket]> error in %s, flag=0x%02x :: "
			    "%s:%i", __func__, flag, __FILE__, __LINE__);
			break;
	}
	return ret;
}

static void dispatch(void *udata, int flag)
{
	usocket_t *sck = udata;

	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return;
	}

	int (*context_handler)(usocket_t *, int) =
	    usocket_context_handler[sck->context];

	if (context_handler(sck, flag) < 0)
		JOURNAL_DEBUG("usocket]> context_handler failed :: %s:%i",
		    __FILE__, __LINE__);
}

static void poke(void *udata)
{
	int *queue = udata;

	if (!queue) {
		JOURNAL_DEBUG("usocket]> poke() called with NULL pointer"
		    " :: %s:%i", __FILE__, __LINE__);
		return;
	}

	if (ion_poke(*queue, dispatch) < 0)
		JOURNAL_DEBUG("usocket]> ion_poke() failure on queue %i: "
		    "%s :: %s:%i", queue, strerror(errno), __FILE__, __LINE__);
}

static usocket_t *factory(const char *sun_path, struct sockaddr_un *sunaddr)
{
	usocket_t *sck = NULL;

	sck = calloc(1, sizeof(usocket_t));
	if (sck == NULL) {
		JOURNAL_DEBUG("usocket]> calloc() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	sck->fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sck->fd < 0) {
		JOURNAL_DEBUG("usocket]> socket() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	sck->buf = fdopen(sck->fd, "r+");
	if (sck->buf == NULL) {
		JOURNAL_DEBUG("usocket]> fdopen() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(sck);
		return NULL;
	}

	memset(sunaddr, 0, sizeof(struct sockaddr_un));
	sunaddr->sun_family = AF_LOCAL;
	strncpy(sunaddr->sun_path, sun_path, sizeof(sunaddr->sun_path));

	return sck;
}

int usocket_close(usocket_t *sck)
{
	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	if (sck->buf) {
		fclose(sck->buf);
	} else {
		close(sck->fd);
	}

	free(sck);
	return 0;
}

int usocket_queue_init(int *queue)
{
	*queue = ion_new();
	if (*queue < 0) {
		JOURNAL_DEBUG("usocket]> ion_new() failed :: %s:%i",
		    __FILE__, __LINE__);
		return -1;
	}

	sched_register(SCHED_APERIODIC, "usocket:poke", poke, 0, queue);
	return 0;
}

int usocket_queue_add(int queue, usocket_t *sck, void *udata)
{
	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	sck->queue = queue;
	sck->udata = udata;

	if (ion_add(queue, sck->fd, sck)) {
		JOURNAL_DEBUG("usocket]> ion_add() failed :: %s:%i",
		    __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

int usocket_listen(usocket_t *sck, int backlog)
{
	if (!sck) {
		JOURNAL_DEBUG("usocket]> %s called with NULL pointer :: %s:%i",
		    __func__, __FILE__, __LINE__);
		return -1;
	}

	if (listen(sck->fd, backlog) < 0) {
		JOURNAL_DEBUG("usocket]> listen() failure: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	sck->context = Q_LISTENER;
	return 0;
}

usocket_t *usocket_create(char *sun_path)
{
	usocket_t *sck = NULL;
	struct sockaddr_un sunaddr;

	sck = factory(sun_path, &sunaddr);
	if (sck == NULL) {
		JOURNAL_DEBUG("usocket]> sck is NULL :: %s:%i",
		    __FILE__, __LINE__);
		return NULL;
	}

	unlink(sun_path);
	if (bind(sck->fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr))) {
		JOURNAL_DEBUG("usocket]> bind() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(sck);
		return NULL;
	}

	return sck;
}

usocket_t *usocket_connect(char *sun_path)
{
	usocket_t *sck = NULL;
	struct sockaddr_un sunaddr;

	sck = factory(sun_path, &sunaddr);
	if (sck == NULL) {
		JOURNAL_DEBUG("usocket]> sck is NULL :: %s:%i",
		    __FILE__, __LINE__);
		return NULL;
	}

	if (connect(sck->fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr))) {
		JOURNAL_DEBUG("usocket]> connect() failed: %s :: %s:%i",
		    strerror(errno), __FILE__, __LINE__);
		usocket_close(sck);
		return NULL;
	}
	sck->context = Q_REMOTE;

	return sck;
}

int usocket_init()
{
	register_context_handler(usocket_context_handler,
	    listener_handler, Q_LISTENER);

	register_context_handler(usocket_context_handler,
	    remote_handler, Q_REMOTE);

	return 0;
}
