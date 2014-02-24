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

#include <unistd.h>

#include <libconfig.h>

#include <logger.h>
#include <netbus.h>

#include "dnd.h"
#include "dsc.h"

#define CONFIG_FILE "/etc/dnds/dnd.conf"

int parse_config(config_t *cfg, struct dnd_cfg *dnd_cfg)
{
	if (!config_read_file(cfg, CONFIG_FILE)) {
		jlog(L_ERROR, "dnd]> Can't open %s", CONFIG_FILE);
		return -1;
	}

	if (config_lookup_string(cfg, "ipaddr", &dnd_cfg->ipaddr))
		jlog(L_DEBUG, "dnd]> ipaddr: %s", dnd_cfg->ipaddr);
	else {
		jlog(L_ERROR, "dnd]> ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "port", &dnd_cfg->port))
		jlog(L_DEBUG, "dnd]> port: %s", dnd_cfg->port);
	else {
		jlog(L_ERROR, "dnd]> port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "dsd_ipaddr", &dnd_cfg->dsd_ipaddr))
		jlog(L_DEBUG, "dnd]> dsd_ipaddr: %s", dnd_cfg->dsd_ipaddr);
	else {
		jlog(L_ERROR, "dnd]> dsd_ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "dsd_port", &dnd_cfg->dsd_port))
		jlog(L_DEBUG, "dnd]> dsd_port: %s", dnd_cfg->dsd_port);
	else {
		jlog(L_ERROR, "dnd]> dsd_port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "certificate", &dnd_cfg->certificate))
		jlog(L_DEBUG, "dnd]> certificate: %s", dnd_cfg->certificate);
	else {
		jlog(L_ERROR, "dnd]> certificate is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "privatekey", &dnd_cfg->privatekey))
		jlog(L_DEBUG, "dnd]> privatekey: %s", dnd_cfg->privatekey);
	else {
		jlog(L_ERROR, "dnd]> privatekey is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "trusted_cert", &dnd_cfg->trusted_cert))
		jlog(L_DEBUG, "dnd]> trusted_cert: %s", dnd_cfg->trusted_cert);
	else {
		jlog(L_ERROR, "dnd]> trusted_cert is not present !");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct dnd_cfg *dnd_cfg;
	config_t cfg;

	if (getuid() != 0) {
		fprintf(stderr, "dnd]> you must be root");
		exit(EXIT_FAILURE);
	}

	dnd_cfg = calloc(1, sizeof(struct dnd_cfg));
	config_init(&cfg);

	if (parse_config(&cfg, dnd_cfg)) {
		jlog(L_ERROR, "dnd]> parse_config failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "dnd]> krypt_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	netbus_tcp_init();
	if (netbus_init()) {
		jlog(L_ERROR, "dnd]> netbus_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (dsc_init(dnd_cfg)) {
		jlog(L_ERROR, "dnd]> dnc_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (dnd_init(dnd_cfg)) {
		jlog(L_ERROR, "dnd]> dnd_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	while (1) { sleep(1); }

	return 0;
}
