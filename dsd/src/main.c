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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include <dnds.h>
#include <event.h>
#include <journal.h>
#include <netbus.h>
#include <options.h>
#include <utils.h>
#include <xsched.h>

#include "dao.h"
#include "dsd.h"

#define CONFIG_FILE "/etc/dnds/dsd.conf"

char *listen_address = NULL;
char *port = NULL;

char *database_host = NULL;
char *database_username = NULL;
char *database_password = NULL;
char *database_name = NULL;

char *certificate = NULL;
char *privatekey = NULL;
char *trusted_authority = NULL;

struct options opts[] = {

	{ "listen_address",	&listen_address,	OPT_STR | OPT_MAN },
	{ "port",		&port,			OPT_STR | OPT_MAN },
	{ "database_host",	&database_host,		OPT_STR | OPT_MAN },
	{ "database_username",	&database_username,	OPT_STR | OPT_MAN },
	{ "database_password",	&database_password,	OPT_STR | OPT_MAN },
	{ "database_name",	&database_name,		OPT_STR | OPT_MAN },
	{ "certificate",	&certificate,		OPT_STR | OPT_MAN },
	{ "privatekey",		&privatekey,		OPT_STR | OPT_MAN },
	{ "trusted_authority",	&trusted_authority,	OPT_STR | OPT_MAN },

	{ NULL }
};

int main(int argc, char *argv[])
{
	int opt, D_FLAG = 0;

	if (getuid() != 0) {
		jlog(L_NOTICE, "%s must be run as root", argv[0]);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "dv")) != -1) {
		switch (opt) {
			case 'd':
				D_FLAG = 1;
				break;
			case 'v':
				printf("beta version\n");
				exit(EXIT_SUCCESS);
	    		default:
				printf("-d , -v\n");
				jlog(L_NOTICE, "dsd]> getopt() failed :: %s:%i", __FILE__, __LINE__);
				exit(EXIT_FAILURE);
		}
	}

	/* State initialization */
	if (option_parse(opts, CONFIG_FILE)) {
		jlog(L_NOTICE, "dsd]> option_parse() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	option_dump(opts);

	/* System initialization */
	if (event_init()) {
		jlog(L_NOTICE, "dsd]> event_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (scheduler_init()) {
		jlog(L_NOTICE, "dsd]> scheduler_init() failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (netbus_init()) {
		jlog(L_NOTICE, "dsd]> netbus_init() failed. :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "dnd]> krypt_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* TODO handle errors */
	pki_init();
	dao_connect(database_host, database_username, database_password, database_name);

	/* Server initialization */
	if (dsd_init(listen_address, port, certificate, privatekey, trusted_authority)) {
		jlog(L_NOTICE, "dsd]> dnds_init() failed. :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (D_FLAG) {
		daemonize();
	}

	/* Now... run ! */
	scheduler();

	return 0;
}
