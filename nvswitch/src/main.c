/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
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

#include <unistd.h>

#include <libconfig.h>
#include <netbus.h>

#include <logger.h>

#include "control.h"
#include "switch.h"

#define CONFIG_FILE "/etc/netvirt/nvswitch.conf"

static struct switch_cfg *switch_cfg;

void
on_log(const char *logline)
{
	fprintf(stdout, "%s", logline);
}

int
config_parse(config_t *cfg, struct switch_cfg *switch_cfg)
{
	if (!config_read_file(cfg, CONFIG_FILE)) {
		jlog(L_ERROR, "Can't open %s", CONFIG_FILE);
		return -1;
	}

        if (config_lookup_string(cfg, "log_file", &switch_cfg->log_file)) {
                jlog_init_file(switch_cfg->log_file);
        }

	if (config_lookup_string(cfg, "listen_ip", &switch_cfg->listen_ip))
		jlog(L_DEBUG, "listen_ip: %s", switch_cfg->listen_ip);
	else {
		jlog(L_ERROR, "listen_ip is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "listen_port", &switch_cfg->listen_port))
		jlog(L_DEBUG, "listen_port: %s", switch_cfg->listen_port);
	else {
		jlog(L_ERROR, "listen_port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "ctrler_ip", &switch_cfg->ctrler_ip))
		jlog(L_DEBUG, "ctrler_ip: %s", switch_cfg->ctrler_ip);
	else {
		jlog(L_ERROR, "ctrler_ip is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "ctrler_port", &switch_cfg->ctrler_port))
		jlog(L_DEBUG, "ctrler_port: %s", switch_cfg->ctrler_port);
	else {
		jlog(L_ERROR, "ctrler_port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "certificate", &switch_cfg->cert))
		jlog(L_DEBUG, "certificate: %s", switch_cfg->cert);
	else {
		jlog(L_ERROR, "certificate is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "privatekey", &switch_cfg->pkey))
		jlog(L_DEBUG, "privatekey: %s", switch_cfg->pkey);
	else {
		jlog(L_ERROR, "privatekey is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "trusted_cert", &switch_cfg->tcert))
		jlog(L_DEBUG, "trusted_cert: %s", switch_cfg->tcert);
	else {
		jlog(L_ERROR, "trusted_cert is not present !");
		return -1;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int		opt;
	uint8_t		quiet = 0;
	config_t	cfg;

	switch_cfg = calloc(1, sizeof(struct switch_cfg));

	while ((opt = getopt(argc, argv, "qvh")) != -1) {
		switch (opt) {
		case 'q':
			quiet = 1;
			break;
		case 'v':
			fprintf(stdout, "netvirt-switch %s\n", NVSWITCH_VERSION);
			return 0;
		default:
		case 'h':
			fprintf(stdout, "netvirt-switch:\n"
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
	switch_cfg->ctrl_initialized = 0;

	if (config_parse(&cfg, switch_cfg)) {
		jlog(L_ERROR, "config parse failed");
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "krypt_init failed");
		exit(EXIT_FAILURE);
	}

	if (netbus_init()) {
		jlog(L_ERROR, "netbus_init failed");
		exit(EXIT_FAILURE);
	}

	if (switch_init(switch_cfg)) {
		jlog(L_ERROR, "switch_init failed");
		exit(EXIT_FAILURE);
	}

	if (ctrl_init(switch_cfg)) {
		jlog(L_ERROR, "ctrl_init failed");
		exit(EXIT_FAILURE);
	}

	while (switch_cfg->switch_running)
		sleep(1);

	/* clean up */
	ctrl_fini();
	switch_fini();
	netbus_fini();
	krypt_fini();
	config_destroy(&cfg);
	free(switch_cfg);

	printf("Goodbye netvirt-switch !\n");

	return 0;
}
