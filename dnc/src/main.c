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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logger.h>
#include "config.h"
#include "dnc.h"

int main(int argc, char *argv[])
{
	int opt;
	struct dnc_cfg *dnc_cfg;
	dnc_cfg = calloc(1, sizeof(struct dnc_cfg));

#ifndef _WIN32
	if (getuid() != 0) {
		jlog(L_ERROR, "dnc]> You must be root !");
		return -1;
	}
#endif

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
		case 'p':
			jlog(L_DEBUG, "dnc]> provisioning code: %s", optarg);
			dnc_cfg->prov_code = strdup(optarg);
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

	return 0;
}

