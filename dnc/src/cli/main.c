/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logger.h>
#include "../config.h"
#include "../dnc.h"

int main(int argc, char *argv[])
{
	int opt;
	struct dnc_cfg *dnc_cfg = NULL;
	dnc_cfg = calloc(1, sizeof(struct dnc_cfg));

	while ((opt = getopt(argc, argv, "vhp:")) != -1) {
		switch (opt) {
		case 'p':
			jlog(L_DEBUG, "dnc]> provisioning code: %s", optarg);
			dnc_cfg->prov_code = strdup(optarg);
			break;
		case 'v':
			jlog(L_NOTICE, "dnc]> version: %s", DNCVERSION);
			return 0;
		case 'h':
			jlog(L_NOTICE, "\nDynVPN client:\n\n"
					"-p KEY\t\tclient provisioning\n"
					"-v\t\tshow version\n"
					"-h\t\tshow this help\n");
			return 0;
		default:
			return 0;
		}
	}

	if (dnc_config_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_config_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	jlog(L_NOTICE, "dnc]> connecting...");

	if (dnc_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	while(1) { sleep(1); }

	return 0;
}

