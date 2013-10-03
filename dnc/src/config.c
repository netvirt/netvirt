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

#include <libconfig.h>

#include <logger.h>
#include "dnc.h"

#ifdef _WIN32
	#define CONFIG_FILE "dnc.conf"
#elif __APPLE__
	#define CONFIG_FILE "dnc.conf"
#else
	#define CONFIG_FILE "/etc/dnds/dnc.conf"
#endif

int dnc_config_init(struct dnc_cfg *dnc_cfg)
{
	config_t cfg;
	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
        if (!config_read_file(&cfg, CONFIG_FILE)) {
                fprintf(stderr, "Can't open %s\n", CONFIG_FILE);
                return(EXIT_FAILURE);
        }

	if (config_lookup_string(&cfg, "log_file", &dnc_cfg->log_file)) {
		jlog_init_file(dnc_cfg->log_file);
	}

        if (config_lookup_string(&cfg, "server_address", &dnc_cfg->server_address))
                jlog(L_DEBUG, "dnc]> server_address: %s", dnc_cfg->server_address);
	else {
		jlog(L_ERROR, "dnc]> server_address is not present !");
		exit(EXIT_FAILURE);
	}

        if (config_lookup_string(&cfg, "server_port", &dnc_cfg->server_port))
                jlog(L_DEBUG, "dnc]> server_port: %s", dnc_cfg->server_port);
	else {
		jlog(L_ERROR, "dnc]> server_port is not present !");
		exit(EXIT_FAILURE);
	}

        if (config_lookup_string(&cfg, "certificate", &dnc_cfg->certificate))
                jlog(L_DEBUG, "dnc]> certificate: %s", dnc_cfg->certificate);
	else {
		jlog(L_ERROR, "dnc]> certificate is not present !");
		exit(EXIT_FAILURE);
	}

        if (config_lookup_string(&cfg, "privatekey", &dnc_cfg->privatekey))
                jlog(L_DEBUG, "dnc]> privatekey: %s", dnc_cfg->privatekey);
	else {
		jlog(L_ERROR, "dnc]> privatekey is not present !");
		exit(EXIT_FAILURE);
	}

        if (config_lookup_string(&cfg, "trusted_cert", &dnc_cfg->trusted_cert))
                jlog(L_DEBUG, "dnc]> trusted_cert: %s", dnc_cfg->trusted_cert);
	else {
		jlog(L_ERROR, "dnc]> trusted_cert is not present !");
		exit(EXIT_FAILURE);
	}

	return 0;
}
