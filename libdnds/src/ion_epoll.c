/*
 * ion_epoll.c: epoll Input/Output notifier API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <sys/epoll.h>
#include <errno.h>
#include <string.h>

#include "ion.h"
#include "journal.h"

static struct epoll_event ep_ev[NUM_EVENTS];
int ion_poke(int queue, void (*notify)(void *udata, int flag))
{
	int nfd, flag, i;

	nfd = epoll_wait(queue, ep_ev, NUM_EVENTS, 1);
	if (nfd < 0) {
		jlog(L_NOTICE, "ion]> epoll_wait() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	for (i = 0; i < nfd; i++) {

		flag = ION_EROR;

		if (ep_ev[i].events & EPOLLRDHUP)
			flag = ION_EROR;
		else if (ep_ev[i].events & EPOLLERR)
			flag = ION_EROR;
		else if (ep_ev[i].events & EPOLLIN)
			flag = ION_READ;

		notify(ep_ev[i].data.ptr, flag);
	}

	return nfd;
}

int ion_add(int queue, int fd, void *udata)
{
	struct epoll_event nevent;
	int ret;

	nevent.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
	nevent.data.ptr = udata;

	ret = epoll_ctl(queue, EPOLL_CTL_ADD, fd, &nevent);
	if (ret < 0)
		jlog(L_NOTICE, "ion]> epoll_ctl() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);

	return ret;
}

int ion_new()
{
	int epoll_fd;

	epoll_fd = epoll_create(BACKING_STORE);
	if (epoll_fd <	0)
		jlog(L_NOTICE, "ion]> epoll_create() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);

	return epoll_fd;
}

