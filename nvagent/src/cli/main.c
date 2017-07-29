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

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/event.h>

#include "../agent.h"

static void		 usage(void);
static void		 sighandler(int, short, void *);

struct event_base	*ev_base = NULL;

void
usage(void)
{
	extern char	*__progname;
	fprintf(stderr, "usage: %s\n"
	    "\t-p\tprovisioning key\n"
	    "\t-n\tnetwork name\n"
	    "\t-l\tlist provisioned networks\n"
	    "\t-h\thelp\n"
	    "\n\tProvisioning a new network: ./%s -p your_provisioning_key "
	    "-n my_new_network\n"
	    "\tConnecting to a provisioned network: ./%s -n my_new_network\n"
	    , __progname, __progname, __progname);
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

	while ((ch = getopt(argc, argv, "hp:n:l")) != -1) {

		switch (ch) {
		case 'p':
			provcode = optarg;
			break;
		case 'n':
			network_name = optarg;
			break;
		case 'l':
			list_networks = 1;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (provcode != NULL && network_name == NULL) {
		fprintf(stderr, "%s: You must specify a network name and"
		    "a provisioning code\n", __func__);
		usage();
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

	if (provcode != NULL && network_name != NULL) {
		if (agent_provisioning(provcode, network_name) < 0)
			usage();
	}

	control_init(network_name);
//	agent_connect(network_name);
//	agent_init();

	event_base_dispatch(ev_base);
	event_base_free(ev_base);

	return (0);
}

