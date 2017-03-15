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

#include "../agent.h"


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
//	struct event	ev_sigint;
//	struct event	ev_sigterm;

/*
	signal_set(&ev_sigint, SIGINT, sighandler, ev_base);
	if (signal_add(&ev_sigint, NULL) < 0)
		errx(1, "signal_add");

	signal_set(&ev_sigterm, SIGTERM, sighandler, ev_base);
	if (signal_add(&ev_sigterm, NULL) < 0)
		errx(1, "signal_add");
*/

//	agent_prov("W1mOpl6pYICUB1-Il8B26HlP$-XkALcRaZxMyhnId9BYQ6qvf$MxsLgHrNU7z088EToITDBfTe0jrTACxo9WSltn6r7J1EfFDp");

	agent_init();

	printf("here\n");
	return 0;

	agent_fini();
	event_base_free(ev_base);

	return (0);
}

