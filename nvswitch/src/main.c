/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
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

#include <signal.h>
#include <unistd.h>

#include <libconfig.h>
#include <logger.h>
#include <netbus.h>

#include "control.h"
#include "switch.h"

#define CONFIG_FILE "/etc/netvirt/switch.conf"

static struct switch_cfg *switch_cfg;
void on_log(const char *logline)
{
	fprintf(stdout, "%s", logline);
}

int config_parse(config_t *cfg, struct switch_cfg *switch_cfg)
{
	if (!config_read_file(cfg, CONFIG_FILE)) {
		jlog(L_ERROR, "Can't open %s", CONFIG_FILE);
		return -1;
	}

        if (config_lookup_string(cfg, "log_file", &switch_cfg->log_file)) {
                jlog_init_file(switch_cfg->log_file);
        }

	if (config_lookup_string(cfg, "ipaddr", &switch_cfg->ipaddr))
		jlog(L_DEBUG, "ipaddr: %s", switch_cfg->ipaddr);
	else {
		jlog(L_ERROR, "ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "port", &switch_cfg->port))
		jlog(L_DEBUG, "port: %s", switch_cfg->port);
	else {
		jlog(L_ERROR, "port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "dsd_ipaddr", &switch_cfg->dsd_ipaddr))
		jlog(L_DEBUG, "dsd_ipaddr: %s", switch_cfg->dsd_ipaddr);
	else {
		jlog(L_ERROR, "dsd_ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "dsd_port", &switch_cfg->dsd_port))
		jlog(L_DEBUG, "dsd_port: %s", switch_cfg->dsd_port);
	else {
		jlog(L_ERROR, "dsd_port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "certificate", &switch_cfg->certificate))
		jlog(L_DEBUG, "certificate: %s", switch_cfg->certificate);
	else {
		jlog(L_ERROR, "certificate is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "privatekey", &switch_cfg->privatekey))
		jlog(L_DEBUG, "privatekey: %s", switch_cfg->privatekey);
	else {
		jlog(L_ERROR, "privatekey is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "trusted_cert", &switch_cfg->trusted_cert))
		jlog(L_DEBUG, "trusted_cert: %s", switch_cfg->trusted_cert);
	else {
		jlog(L_ERROR, "trusted_cert is not present !");
		return -1;
	}

	return 0;
}

void int_handler(int sig)
{
	(void)sig;

	if (switch_cfg->dsc_running && switch_cfg->switch_running) {
		switch_cfg->dsc_running = 0;
		switch_cfg->switch_running = 0;
	}
}

int main(int argc, char *argv[])
{
	int opt;
	uint8_t quiet = 0;
	config_t cfg;
	switch_cfg = calloc(1, sizeof(struct switch_cfg));

	signal(SIGINT, int_handler);

	while ((opt = getopt(argc, argv, "qvh")) != -1) {
		switch (opt) {
		case 'q':
			quiet = 1;
			break;
		case 'v':
			fprintf(stdout, "NetVirt switch server version: %s\n", DNDVERSION);
			return 0;
		default:
		case 'h':
			fprintf(stdout, "\nNetVirt switch server:\n\n"
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
	switch_cfg->dsc_initialized = 0;

	if (config_parse(&cfg, switch_cfg)) {
		jlog(L_ERROR, "config parse failed");
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

	if (dsc_init(switch_cfg)) {
		jlog(L_ERROR, "dsc_init failed");
		exit(EXIT_FAILURE);
	}

	/* make sure dsc is properly initialized before
		accepting connection */
	while (switch_cfg->dsc_initialized == 0) {
		sleep(1);
	}

	if (switch_init(switch_cfg)) {
		jlog(L_ERROR, "switch_init failed");
		exit(EXIT_FAILURE);
	}

	while (switch_cfg->dsc_running || switch_cfg->switch_running) {
		sleep(1);
	}

	/* clean up */
	dsc_fini();
	switch_fini();
	netbus_fini();
	config_destroy(&cfg);
	free(switch_cfg);

	printf("Goodbye nvswitch !\n");

	return 0;
}
