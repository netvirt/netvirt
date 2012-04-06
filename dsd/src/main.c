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

#include <dnds/dnds.h>
#include <dnds/event.h>
#include <dnds/hooklet.h>
#include <dnds/journal.h>
#include <dnds/netbus.h>
#include <dnds/options.h>
#include <dnds/utils.h>
#include <dnds/xsched.h>

#include "config.h"
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
		JOURNAL_NOTICE("%s must be run as root", argv[0]);
		_exit(EXIT_ERR);
	}

	while ((opt = getopt(argc, argv, "dv")) != -1) {
		switch (opt) {
			case 'd':
				D_FLAG = 1;
				break;
			case 'v':
				printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
				exit(EXIT_SUCCESS);
	    		default:
				printf("-d , -v\n");
				JOURNAL_NOTICE("dsd]> getopt() failed :: %s:%i", __FILE__, __LINE__);
				_exit(EXIT_ERR);
		}
	}

	if (option_parse(opts, CONFIG_FILE)) {
		JOURNAL_NOTICE("dsd]> option_parse() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	option_dump(opts);

	/* Subsystems initialization */

	if (event_init()) {
		JOURNAL_NOTICE("dsd]> event_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (scheduler_init()) {
		JOURNAL_NOTICE("dsd]> scheduler_init() failed :: %s:%i\n", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (netbus_init()) {
		JOURNAL_NOTICE("dsd]> netbus_init() failed. :: %s:%i\n", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	krypt_init();
	pki_init();

	dao_connect(database_host, database_username, database_password, database_name);

	if (dsd_init(listen_address, port, certificate, privatekey, trusted_authority)) {
		JOURNAL_NOTICE("dsd]> dnds_init() failed. :: %s:%i\n", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	if (D_FLAG) {
		daemonize();
		journal_set_lvl(1);
	}

	scheduler();

	return 0;
}
