/*
 * event.c: Event notifier API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */


#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "event.h"
#include "journal.h"

static event_t *events[EVENT_MAX] = {NULL};
extern int event_register(int EVENT, char *name, void (*cb)(void *), int prio)
{
	event_t *ev_itr, *ev;

	ev = malloc(sizeof(event_t));
	if (ev == NULL) {
		jlog(L_DEBUG, "event]> malloc() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	ev_itr = ev;

	ev->name = strdup(name);
	ev->cb = cb;
	ev->prio = prio;

	if (events[EVENT] == NULL) {

		events[EVENT] = ev;
		ev->next = NULL;

	} else if (prio == PRIO_HIGH) {

	ev->next = events[EVENT];
	events[EVENT] = ev;

	} else if (prio == PRIO_LOW) {

	ev_itr = events[EVENT];
	while (ev_itr->next != NULL)
		ev_itr = ev_itr->next;
	ev_itr->next = ev;
	ev->next = NULL;

	} else if (prio == PRIO_AGNOSTIC) {

		if (events[EVENT]->prio == PRIO_AGNOSTIC) {

			ev->next = events[EVENT];
			events[EVENT] = ev;

		} else if (events[EVENT]->prio == PRIO_HIGH) {

			ev_itr = events[EVENT];
			while (ev_itr->next != NULL && ev_itr->next->prio == PRIO_HIGH)
				ev_itr = ev_itr->next;
			ev->next = ev_itr->next;
			ev_itr = ev;

		} else if (events[EVENT]->prio == PRIO_LOW) {

			ev->next = events[EVENT];
			events[EVENT] = ev;
		}
	}

    return 0;
}

extern void event_throw(int EVENT, void *data)
{
	event_t *ev;
	ev = events[EVENT];
	jlog(L_NOTICE, "event]> throw::%i", EVENT);

	while (ev) {
		jlog(L_NOTICE, "event]> %s", ev->name);
		ev->cb(data);
		ev = ev->next;
	}

	// XXX is it really my job to free the data !!?
	if (data != NULL)
		free(data);

	return;
}

static int caught_sigsev = 0;
static void sig_handler(int signum, siginfo_t *info, void *ucontext)
{
	int ret;

	sigset_t block_mask, old_mask;

	ret = sigfillset(&block_mask);
	ret = sigprocmask(SIG_BLOCK, &block_mask, &old_mask);

	switch (signum) {

		case SIGSEGV:
			jlog(L_NOTICE, "event]> caught SIGSEGV :: %s:%i", __FILE__, __LINE__);
			event_throw(EVENT_EXIT, NULL);
			if (caught_sigsev == 0)
				caught_sigsev = 1;
			else {
				jlog(L_ERROR, "event]> system failure, SIGSEGV loop detected :: %s%i", __FILE__, __LINE__);
				_exit(-1);
			}

			break;
		case SIGINT:
			jlog(L_NOTICE, "event]> caught SIGINT :: %s:%i", __FILE__, __LINE__);
			event_throw(EVENT_EXIT, NULL);
			break;

		case SIGALRM:
			event_throw(EVENT_SCHED, NULL);
			break;
	}

	sigprocmask(SIG_SETMASK, &old_mask, NULL);

	return;
}

extern int event_init()
{
	struct sigaction act;
	sigset_t block_mask;

	/* We need a special hander to catch special signals */
	sigfillset(&block_mask);

	act.sa_sigaction = sig_handler;
	act.sa_mask = block_mask;
	act.sa_flags = 0;

	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGIO, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);

	return 0;
}
