/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2017
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
#include <syslog.h>
#include <unistd.h>

#include <event2/event.h>

#include <log.h>

#include "switch.h"

#define CONFIG_FILE "/etc/netvirt/nvswitch.conf"

static void sighandler(int, short, void *);

json_t			*config = NULL;
struct event_base	*ev_base = NULL;

void
sighandler(int signal, short events, void *arg)
{
	event_base_loopbreak(arg);
}

int
main(int argc, char *argv[])
{
	json_error_t		 error;
	struct event		*ev_sigint;
	struct event		*ev_sigterm;
//	extern	int		 control_init_done;

	log_init(2, LOG_DAEMON);

	if ((config = json_load_file(CONFIG_FILE, 0, &error)) == NULL)
		fatalx("json_load_file: line: %d error: %s",
		    error.line, error.text);

	if ((ev_base = event_base_new()) == NULL)
		fatalx("event_base_new");

	if ((ev_sigint = evsignal_new(ev_base, SIGINT, sighandler, ev_base))
	    == NULL)
		fatalx("evsignal_new SIGINT");
	event_add(ev_sigint, NULL);

	if ((ev_sigterm = evsignal_new(ev_base, SIGTERM, sighandler, ev_base))
	    == NULL)
		fatalx("evsignal_new SIGTERM");
	event_add(ev_sigterm, NULL);

	control_init();

//	while (control_initialized == 0)
//		sleep(1);
//	switch_init(config);

	json_decref(config);
	event_base_dispatch(ev_base);
	event_free(ev_sigint);
	event_free(ev_sigterm);
	event_base_free(ev_base);

//	switch_fini();

	warnx("now off");

	return 0;
}
