/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
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
#include <stdlib.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/thread.h>

#include "../agent.h"

static void		 usage(void);
static void		 sighandler(int, short, void *);

struct event_base	*ev_base = NULL;

void
usage(void)
{
	extern char	*__progname;
	fprintf(stderr, "usage: %s\n"
	    "\t-k\tConfigure new network [provisioning key]\n"
	    "\t-l\tList networks\n"
	    "\t-c\tConnect [network name]\n"
	    "\t-h\thelp\n", __progname);
	exit(1);
}

void
sighandler(int signal, short events, void *arg)
{
	(void)signal;
	(void)events;

	event_base_loopbreak(arg);
}

int
main(int argc, char *argv[])
{
	struct event	*ev_sigint;
	struct event	*ev_sigterm;
	int		 ch;
	int		 list_networks = 0;
	char		*provcode = NULL;
	char		*network_name = NULL;
	char		 new_name[64];

	while ((ch = getopt(argc, argv, "hk:lc:")) != -1) {

		switch (ch) {
		case 'k':
			provcode = optarg;
			break;
		case 'l':
			list_networks = 1;
			break;
		case 'c':
			network_name = optarg;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

#ifdef _WIN32
        WORD wVersionRequested = MAKEWORD(1,1);
        WSADATA wsaData;
        WSAStartup(wVersionRequested, &wsaData);
#endif

#if defined(_WIN32) || defined(__APPLE__)
	evthread_use_pthreads();
#endif

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "%s: signal", __func__);
		exit(-1);
	}

	if (ndb_init() < 0) {
		fprintf(stderr, "%s: db_init\n", __func__);
		exit(-1);
	}

	if (list_networks) {
		ndb_networks();
		exit(0);
	}

	if ((ev_base = event_base_new()) == NULL) {
		fprintf(stderr, "%s: event_init\n", __func__);
		exit(-1);
	}

	if ((ev_sigint = evsignal_new(ev_base, SIGINT, sighandler, ev_base))
	    == NULL) {
		fprintf(stderr, "%s: evsignal_new\n", __func__); 
		exit(-1);
	}
	event_add(ev_sigint, NULL);

	if ((ev_sigterm = evsignal_new(ev_base, SIGTERM, sighandler, ev_base))
	    == NULL) {
		fprintf(stderr, "%s: evsignal_new\n", __func__);
		exit(-1);
	}
	event_add(ev_sigterm, NULL);

	char *p;
	if (provcode != NULL) {
		printf("Give this network a name: ");
		if (fgets(new_name, sizeof(new_name)-1, stdin) == NULL)
			errx(0, "fgets");

		if ((p = strchr(new_name, '\n')) != NULL)
			*p = '\0';

		if (ndb_provisioning(provcode, new_name) < 0)
			usage();

	} else if (network_name)
		control_init(network_name);

	event_base_dispatch(ev_base);

	event_free(ev_sigint);
	event_free(ev_sigterm);
	event_base_free(ev_base);

	return (0);
}

