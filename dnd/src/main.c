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

#include <event.h>
#include <hooklet.h>
#include <journal.h>
#include <netbus.h>
#include <options.h>
#include <udtbus.h>
#include <xsched.h>

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
		exit(EXIT_FAILURE);
	}

	/* State initialization */
	if (option_parse(opts, CONFIG_FILE)) {
		jlog(L_ERROR, "dnd]> option_parse() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	option_dump(opts);

	/* System initialization */
	if (event_init()) {
		jlog(L_ERROR, "dnd]> event_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (scheduler_init()) {
		jlog(L_ERROR, "dnd]> scheduler_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (udtbus_init()) {
		jlog(L_ERROR, "dnd]> udtbus_init() faled :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (netbus_init()) {
		jlog(L_ERROR, "dnd]> netbus_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "dnd]> krypt_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* Connect to the Directory Service */
	if (dsc_init(dsc_address, dsc_port, certificate, privatekey, trusted_authority)) {
		jlog(L_ERROR, "dnd]> dnc_init() failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* Server initialization */
	if (dnd_init(listen_address, listen_port)) {
		jlog(L_ERROR, "dnd]> dnd_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* Now... run ! */
	scheduler();

	return 0;
}
