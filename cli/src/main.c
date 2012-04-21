/*
 * main.c: DNDS command line interface
 * Copyright 2012. Jamael Seun
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <dnds/cli.h>
#include <dnds/journal.h>
#include <dnds/options.h>
#include <dnds/xsched.h>

#include "command.h"

#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/dnds/dndscli.conf"
#endif

char *dnc_unix_socket = NULL;
char *dnd_unix_socket = NULL;
char *dsd_unix_socket = NULL;

struct options opts[] = {

	{ "dnc_unix_socket",	&dnc_unix_socket,	OPT_STR },
	{ "dnd_unix_socket",	&dnd_unix_socket,	OPT_STR },
	{ "dsd_unix_socket",	&dsd_unix_socket,	OPT_STR },

	{ NULL }
};

#define ARGS_TARGET		0x1
#define ARGS_NOCOMPLETE		0x2
int main(int argc, char *argv[])
{
	cli_console_t *console = NULL;
	char *unix_socket = NULL;
	int c, args;

	if (option_parse(opts, CONFIG_FILE)) {
		JOURNAL_ERR("cannot parse configuration file");
		_exit(EXIT_ERR);
	}

	while ((c = getopt(argc, argv, "at:")) != -1) {
		switch(c) {
		case 'a': /* disable command completion */
			args |= ARGS_NOCOMPLETE;
			break;
		case 't': /* use target from config file */
			if (!strcmp(optarg, "dnc")) {
				unix_socket = dnc_unix_socket;
			} else if (!strcmp(optarg, "dnd")) {
				unix_socket = dnd_unix_socket;
			} else if (!strcmp(optarg, "dsd")) {
				unix_socket = dsd_unix_socket;
			}
			args |= ARGS_TARGET;
			break;
		}
	}

	if (!unix_socket) {
		JOURNAL_ERR("no socket specified; use -t <target>");
		_exit(EXIT_ERR);
	}

	if (scheduler_init()) {
		JOURNAL_ERR("initializing scheduler failed");
		_exit(EXIT_ERR);
	}

	/* ignore broken pipe signal */
	signal(SIGPIPE, SIG_IGN);

	console = cli_console_init(unix_socket);
	if (!console) {
		JOURNAL_ERR("unable to connect to specified socket");
		_exit(EXIT_ERR);
	}

	command_init(console->socket);

	if (command_list_fetch(console->socket)) {
		JOURNAL_NOTICE("cannot get command list from target");
	}

	if (args & ARGS_NOCOMPLETE) {
		JOURNAL_NOTICE("command completion is off");
	} else
		command_set_completion();

	scheduler();

	/* program is closing */
	cli_console_fini(console);

	return 0;
}
