/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <unistd.h>

#include <dnds/event.h>
#include <dnds/hooklet.h>
#include <dnds/journal.h>
#include <dnds/netbus.h>
#include <dnds/options.h>
#include <dnds/udtbus.h>
#include <dnds/xsched.h>

#include "dnd.h"
#include "dsc.h"

#define CONFIG_FILE "/etc/dnds/dnd.conf"

char *listen_address = NULL;
char *listen_port = NULL;

char *dsc_address = NULL;
char *dsc_port = NULL;

char *certificate = NULL;
char *privatekey = NULL;
char *trusted_authority = NULL;

struct options opts[] = {

	{ "listen_address",	&listen_address,	OPT_STR | OPT_MAN },
	{ "listen_port",	&listen_port,		OPT_STR | OPT_MAN },
	{ "dsc_address",	&dsc_address,		OPT_STR | OPT_MAN },
	{ "dsc_port",		&dsc_port,		OPT_STR | OPT_MAN },
	{ "certificate",	&certificate,		OPT_STR | OPT_MAN },
	{ "privatekey",		&privatekey,		OPT_STR | OPT_MAN },
	{ "trusted_authority",	&trusted_authority,	OPT_STR | OPT_MAN },

	{ NULL }
};

int main(int argc, char *argv[])
{
	if (getuid() != 0) {
		fprintf(stderr, "dnd]> you must be root\n");
		_exit(EXIT_NOT_ROOT);
	}

	/* State initialization */
	if (option_parse(opts, CONFIG_FILE)) {
		JOURNAL_ERR("dnd]> option_parse() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	option_dump(opts);

	/* System initialization */
	if (event_init()) {
		JOURNAL_ERR("dnd]> event_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (scheduler_init()) {
		JOURNAL_ERR("dnd]> scheduler_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (udtbus_init()) {
		JOURNAL_ERR("dnd]> udtbus_init() faled :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (netbus_init()) {
		JOURNAL_ERR("dnd]> netbus_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (krypt_init()) {
		JOURNAL_ERR("dnd]> krypt_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	/* Server initialization */
	if (dsc_init(dsc_address, dsc_port, certificate, privatekey, trusted_authority)) {
		JOURNAL_ERR("dnd]> dnc_init() failed :: %s:%i\n", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (dnd_init(listen_address, listen_port)) {
		JOURNAL_ERR("dnd]> dnd_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	/* Now... run ! */
	scheduler();

	return 0;
}
