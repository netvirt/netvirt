/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details
 */

#include <err.h>
#include <signal.h>
#include <unistd.h>

#include <event.h>

#include "control.h"
#include "switch.h"

#define CONFIG_FILE "/etc/netvirt/nvswitch.conf"

struct event_base	*ev_base;

static void	usage(void);

void
usage(void)
{
	extern char	*__progname;
	fprintf(stdout, "%s:\n"
	    "-q\t\tquiet mode\n"
	    "-v\t\tshow version\n"
	    "-h\t\tthis message\n"
	    ,__progname);

	exit(-1);
}

void
sighandler(int signal, short events, void *arg)
{
	printf("sighandler\n");
	event_base_loopbreak(arg);
}

int
main(int argc, char *argv[])
{
	json_t			*config;
	json_error_t		 error;
	struct event		 ev_sigint;
	struct event		 ev_sigterm;
	int			 ch;

	while ((ch = getopt(argc, argv, "vh")) != -1) {
		switch (ch) {
		case 'v':
			fprintf(stdout, "netvirt-switch %s\n", NVSWITCH_VERSION);
			return (0);
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((config = json_load_file(CONFIG_FILE, 0, &error)) == NULL)
		errx(1, "json_load_file: line: %d - %s",
		    error.line, error.text);

	if ((ev_base = event_init()) == NULL)
		errx(1, "event_base_new");

	signal_set(&ev_sigint, SIGINT, sighandler, ev_base);
	if (signal_add(&ev_sigint, NULL) < 0)
		errx(1, "signal_add");

	signal_set(&ev_sigterm, SIGTERM, sighandler, ev_base);
	if (signal_add(&ev_sigterm, NULL) < 0)
		errx(1, "signal_add");

	switch_init(config);

/*
	printf("%s\n", json_dumps(json, JSON_COMPACT|JSON_INDENT(1)|JSON_PRESERVE_ORDER));
	control_init();
*/
	event_base_dispatch(ev_base);

	switch_fini();
	json_decref(config);
	event_base_free(ev_base);

	warnx("now off");

	return 0;
}
