/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <sys/stat.h>

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>

#include <event2/event.h>

#include <jansson.h>

#include <log.h>
#include <pki.h>

#include "controller.h"
#include "dao.h"

#define CONFIG_FILE "/etc/netvirt/nvctrler.conf"

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
	int			 ch;
	const char		*dbname;
	const char		*dbuser;
	const char		*dbpwd;
	const char		*dbhost;


	while ((ch = getopt(argc, argv, "bh")) != -1) {
		switch (ch) {
		case 'b':
			pki_bootstrap_certs();
			return 0;
		case 'h':
			fprintf(stdout, "netvirt-controller:\n"
				"-b\t\tbootstrap certificates\n"
				"-v\t\tshow version\n");
			return 0;
		}
	}
	argc -= optind;
	argv += optind;

	log_init(2, LOG_DAEMON);

	if ((config = json_load_file(CONFIG_FILE, 0, &error)) == NULL)
		fatalx("json_load_file line: %d error: %s",
		    error.line, error.text);

	if (json_unpack(config, "{s:s}", "dbname", &dbname) < 0)
		fatalx("dbname not found in config");

	if (json_unpack(config, "{s:s}", "dbuser", &dbuser) < 0)
		fatalx("dbuser not found in config");

	if (json_unpack(config, "{s:s}", "dbpwd", &dbpwd) < 0)
		fatalx("dbpwd not found in config");

	if (json_unpack(config, "{s:s}", "dbhost", &dbhost) < 0)
		fatalx("dbhost not found in config");

	if ((ev_base = event_base_new()) == NULL)
		fatalx("event_init");

	if ((ev_sigint = evsignal_new(ev_base, SIGINT, sighandler, ev_base))
	    == NULL)
		fatalx("evsignal_new SIGINT");
	event_add(ev_sigint, NULL);

	if ((ev_sigterm = evsignal_new(ev_base, SIGTERM, sighandler, ev_base))
	    == NULL)
		fatalx("evsignal_new SIGTERM");
	event_add(ev_sigterm, NULL);

	if (dao_init(dbname, dbuser, dbpwd, dbhost) < 0)
		fatalx("%s: dao_init", __func__);

	if (controller_init(config, ev_base) < 0)
		fatalx("controller_init");

	if (restapi_init(config, ev_base) < 0)
		fatalx("prov_init");

	event_base_dispatch(ev_base);

	controller_fini();
	dao_fini();

	log_info("now off");

	return 0;
}
