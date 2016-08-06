/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
 * Nicolas J. Bouliane <nib@m4nt.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <err.h>
#include <signal.h>

#include <event.h>

#include "../agent.h"

struct event_base	*ev_base;

void
sighandler(int signal, short events, void *arg)
{
	(void)signal;
	(void)events;

	event_base_loopbreak(arg);
}

int
main()
{
	struct event	ev_sigint;
	struct event	ev_sigterm;

	if ((ev_base = event_init()) == NULL)
		errx(1, "event_base_new");

	signal_set(&ev_sigint, SIGINT, sighandler, ev_base);
	if (signal_add(&ev_sigint, NULL) < 0)
		errx(1, "signal_add");

	signal_set(&ev_sigterm, SIGTERM, sighandler, ev_base);
	if (signal_add(&ev_sigterm, NULL) < 0)
		errx(1, "signal_add");

	agent_init();

	event_base_dispatch(ev_base);

	agent_fini();
	event_base_free(ev_base);

	return (0);
}

