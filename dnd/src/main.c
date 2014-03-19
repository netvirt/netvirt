/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details
 */

#include <unistd.h>

#include <libconfig.h>
#include <logger.h>
#include <netbus.h>

#include "dnd.h"
#include "dsc.h"

#define CONFIG_FILE "/etc/dnds/dnd.conf"

void on_log(const char *logline)
{
	fprintf(stdout, "%s", logline);
}

int parse_config(config_t *cfg, struct dnd_cfg *dnd_cfg)
{
	if (!config_read_file(cfg, CONFIG_FILE)) {
		jlog(L_ERROR, "Can't open %s", CONFIG_FILE);
		return -1;
	}

        if (config_lookup_string(cfg, "log_file", &dnd_cfg->log_file)) {
                jlog_init_file(dnd_cfg->log_file);
        }

	if (config_lookup_string(cfg, "ipaddr", &dnd_cfg->ipaddr))
		jlog(L_DEBUG, "ipaddr: %s", dnd_cfg->ipaddr);
	else {
		jlog(L_ERROR, "ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "port", &dnd_cfg->port))
		jlog(L_DEBUG, "port: %s", dnd_cfg->port);
	else {
		jlog(L_ERROR, "port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "dsd_ipaddr", &dnd_cfg->dsd_ipaddr))
		jlog(L_DEBUG, "dsd_ipaddr: %s", dnd_cfg->dsd_ipaddr);
	else {
		jlog(L_ERROR, "dsd_ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "dsd_port", &dnd_cfg->dsd_port))
		jlog(L_DEBUG, "dsd_port: %s", dnd_cfg->dsd_port);
	else {
		jlog(L_ERROR, "dsd_port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "certificate", &dnd_cfg->certificate))
		jlog(L_DEBUG, "certificate: %s", dnd_cfg->certificate);
	else {
		jlog(L_ERROR, "certificate is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "privatekey", &dnd_cfg->privatekey))
		jlog(L_DEBUG, "privatekey: %s", dnd_cfg->privatekey);
	else {
		jlog(L_ERROR, "privatekey is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "trusted_cert", &dnd_cfg->trusted_cert))
		jlog(L_DEBUG, "trusted_cert: %s", dnd_cfg->trusted_cert);
	else {
		jlog(L_ERROR, "trusted_cert is not present !");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int opt;
	uint8_t quiet = 0;
	struct dnd_cfg *dnd_cfg;
	config_t cfg;
	dnd_cfg = calloc(1, sizeof(struct dnd_cfg));

	while ((opt = getopt(argc, argv, "qvh")) != -1) {
		switch (opt) {
		case 'q':
			quiet = 1;
			break;
		case 'v':
			fprintf(stdout, "version: %s\n", DNDVERSION);
			return 0;
		default:
		case 'h':
			fprintf(stdout, "\nDynVPN dnd server:\n\n"
					"-q\t\tquiet mode\n"
					"-v\t\tshow version\n"
					"-h\t\tshow this help\n");
			return 0;
		}
	}

	if (!quiet) {
		jlog_init_cb(on_log);
	}

	config_init(&cfg);

	if (parse_config(&cfg, dnd_cfg)) {
		jlog(L_ERROR, "parse_config failed");
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "krypt_init failed");
		exit(EXIT_FAILURE);
	}

	netbus_tcp_init();
	if (netbus_init()) {
		jlog(L_ERROR, "netbus_init failed");
		exit(EXIT_FAILURE);
	}

	if (dsc_init(dnd_cfg)) {
		jlog(L_ERROR, "dsc_init failed");
		exit(EXIT_FAILURE);
	}

	if (dnd_init(dnd_cfg)) {
		jlog(L_ERROR, "dnd_init failed");
		exit(EXIT_FAILURE);
	}

	while (1) { sleep(1); }

	return 0;
}
