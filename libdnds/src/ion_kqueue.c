/*
 * ion_kqueue.c: kqueue Input/Output notifier API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <errno.h>

#include "ion.h"
#include "journal.h"

static struct kevent kq_ev[NUM_EVENTS];
int ion_poke(int queue, void (*notify)(void *udata, int flag))
{
	int nfd, flag, i;
	struct timespec tmout = {0, 0};

	nfd = kevent(queue, 0, 0, kq_ev, NUM_EVENTS, &tmout);
	if (nfd < 0) {
		JOURNAL_NOTICE("ion]> kevent() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	for (i = 0; i < nfd; i++) {

		flag = ION_EROR;

		if (kq_ev[i].flags & EV_EOF)
			flag = ION_EROR;
		else if (kq_ev[i].flags & EV_ERROR)
			flag = ION_EROR;
		else if (kq_ev[i].flags & EVFILT_READ)
			flag = ION_READ;

		notify(kq_ev[i].udata, flag);
	}

	return nfd;
}

int ion_add(int queue, int fd, void *udata)
{
	struct kevent chlist;
	int ret;
	struct timespec tmout = {0, 0};

	EV_SET(&chlist, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, udata);

	ret = kevent(queue, &chlist, 1, 0, 0, &tmout);
	if (ret < 0)
		JOURNAL_NOTICE("ion]> kevent() %s :: %s%i", strerror(errno), __FILE__, __LINE__);

	return ret;
}

int ion_new()
{
	int kqueue_fd;

	kqueue_fd = kqueue();
	if (kqueue_fd < 0)
		JOURNAL_NOTICE("ion]> kqueue() %s :: %s%i", strerror(errno), __FILE__, __LINE__);

	return kqueue_fd;
}
