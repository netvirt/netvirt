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

#include <libconfig.h>
#include <unistd.h>

#include <crypto.h>
#include <logger.h>
#include <netbus.h>
#include "dnc.h"

#define CONFIG_FILE "/etc/dnds/dnc.conf"

int main(int argc, char *argv[])
{
	int opt;
	char *prov_code = NULL;
	struct dnc_cfg *dnc_cfg;
	config_t cfg;

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

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
        if (!config_read_file(&cfg, CONFIG_FILE)) {
                fprintf(stderr, "Can't open %s\n", CONFIG_FILE);
                return(EXIT_FAILURE);
        }

	dnc_cfg = calloc(1, sizeof(struct dnc_cfg));

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
/*
	if (netbus_init()) {
		jlog(L_ERROR, "dnc]> netbus_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "dnc]> krypt_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
*/
	jlog(L_NOTICE, "dnc]> connecting...");

	if (dnc_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}


	return 0;
}

