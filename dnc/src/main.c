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
#include <journal.h>
#include <net.h>
#include <netbus.h>
#include <options.h>
#include <xsched.h>

#include "dnc.h"
#include "session.h"

#define CONFIG_FILE "/etc/dnds/dnc.conf"

char *server_address = NULL;
char *server_port = NULL;
char *certificate = NULL;
char *privatekey = NULL;
char *trusted_authority = NULL;

struct options opts[] = {

	{ "server_address",	&server_address,	OPT_STR | OPT_MAN },
	{ "server_port",	&server_port,		OPT_STR | OPT_MAN },
	{ "certificate",	&certificate,		OPT_STR | OPT_MAN },
	{ "privatekey",		&privatekey,		OPT_STR | OPT_MAN },
	{ "trusted_authority",	&trusted_authority,	OPT_STR | OPT_MAN },
	{ NULL }
};

int main(int argc, char *argv[])
{
	int opt;
	char *prov_code = NULL;

	if (getuid() != 0) {
		jlog(L_ERROR, "dnc]> You must be root !");
		return -1;
	}

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
		case 'p':
			jlog(L_DEBUG, "provisioning code: %s", optarg);
			prov_code = strdup(optarg);
		}
	}

	if (option_parse(opts, CONFIG_FILE)) {
		jlog(L_ERROR, "dnc]> option_parse() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	option_dump(opts);

	if (event_init()) {
		jlog(L_ERROR, "dnc]> event_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (scheduler_init()) {
		jlog(L_ERROR, "dnc]> scheduler_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (netbus_init()) {
		jlog(L_ERROR, "dnc]> netbus_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	krypt_init();

	jlog(L_NOTICE, "dnc]> connecting...");

	if (dnc_init(server_address, server_port, prov_code, certificate, privatekey, trusted_authority)) {
		jlog(L_ERROR, "dnc]> dnc_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	scheduler();

	return 0;
}

