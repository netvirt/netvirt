/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logger.h>

#include "../agent.h"
#include "../config.h"

void int_handler(int sig)
{
	(void)sig;
	exit(0);
}

void on_log(const char *logline)
{
	fprintf(stdout, "%s", logline);
}

int main(int argc, char *argv[])
{
	int opt;
	struct dnc_cfg *dnc_cfg = NULL;
	dnc_cfg = calloc(1, sizeof(struct dnc_cfg));

	signal(SIGINT, int_handler);

	while ((opt = getopt(argc, argv, "vhp:")) != -1) {
		switch (opt) {
		case 'p':
			fprintf(stdout, "provisioning code: %s\n", optarg);
			dnc_cfg->prov_code = strdup(optarg);
			break;
		case 'v':
			fprintf(stdout, "version: %s\n", DNCVERSION);
			fprintf(stdout, "%s\n", "Licensing Information: http://www.dynvpn.com/license");
			return 0;
		case 'h':
			fprintf(stdout, "\nDynVPN client:\n\n"
					"-p KEY\t\tclient provisioning\n"
					"-v\t\tshow version\n"
					"-h\t\tshow this help\n");
			return 0;
		default:
			return 0;
		}
	}

	dnc_cfg->ev.on_log = on_log;

	if (dnc_config_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc_config_init failed");
		exit(EXIT_FAILURE);
	}

	jlog(L_NOTICE, "connecting...");

	if (dnc_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc_init failed");
		exit(EXIT_FAILURE);
	}

	while(1) { sleep(1); }

	return 0;
}

