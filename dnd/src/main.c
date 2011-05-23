/*
 * Copyright (C) 2010 Nicolas Bouliane
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
#include <dnds/xsched.h>

#include "dnd.h"
#include "dsc.h"

#ifndef CONFIG_FILE
# define CONFIG_FILE "/usr/local/etc/dnds/dnd.conf"
#endif

char *listen_address = NULL;
char *listen_port = NULL;

char *certificate = NULL;
char *privatekey = NULL;
char *trusted_authority = NULL;

struct options opts[] = {

	{ "listen_address",	&listen_address,	OPT_STR | OPT_MAN },
	{ "listen_port",	&listen_port,		OPT_STR | OPT_MAN },
	{ "certificate",	&certificate,		OPT_STR | OPT_MAN },
	{ "privatekey",		&privatekey,		OPT_STR | OPT_MAN },
	{ "trusted_authority",	&trusted_authority,	OPT_STR | OPT_MAN },

	{ NULL }
};

static bool is_root() {
	return (getuid() == 0);
}

int main(int argc, char *argv[])
{
	if (!is_root()) {
		fprintf(stderr, "dnd]> you must be root\n");
		_exit(EXIT_NOT_ROOT);
	}

	// State initialization
	if (option_parse(opts, CONFIG_FILE)) {
		JOURNAL_ERR("dnd]> option_parse() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	option_dump(opts);

	// Systems initialization
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
/*
	if (dsc_init("127.0.0.1", "9090", certificate, privatekey, trusted_authority)) {
		JOURNAL_ERR("dnd]> dnc_init() failed :: %s:%i\n", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}
*/
	if (dnd_init(listen_address, listen_port)) {
		JOURNAL_ERR("dnd]> dnd_init() failed :: %s:%i", __FILE__, __LINE__);
		_exit(EXIT_ERR);
	}

	// Now... run !
	scheduler();

	return 0;
}
