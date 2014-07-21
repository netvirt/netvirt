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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libconfig.h>

#include <dnds.h>
#include <logger.h>
#include <netbus.h>

#include "ctrler.h"
#include "dao.h"

#define CONFIG_FILE "/etc/dnds/dsd.conf"

static struct dsd_cfg *dsd_cfg;
void on_log(const char *logline)
{
        fprintf(stdout, "%s", logline);
}

int daemonize()
{
	pid_t pid, sid;

	if (getppid() == 1)
		return 0;

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);

	sid = setsid();

	if (sid < 0)
		exit(EXIT_FAILURE);

	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	if (freopen("/dev/null", "r", stdin) == NULL)
		return -1;

	if (freopen("/dev/null", "w", stdout) == NULL)
		return -1;

	if (freopen("/dev/null", "w", stderr) == NULL)
		return -1;

	return 0;
}

int parse_config(config_t *cfg, struct dsd_cfg *dsd_cfg)
{
	if (!config_read_file(cfg, CONFIG_FILE)) {
		jlog(L_ERROR, "Can't open %s", CONFIG_FILE);
		return -1;
	}

        if (config_lookup_string(cfg, "log_file", &dsd_cfg->log_file)) {
                jlog_init_file(dsd_cfg->log_file);
        }

	if (config_lookup_string(cfg, "ipaddr", &dsd_cfg->ipaddr))
		jlog(L_DEBUG, "ipaddr: %s", dsd_cfg->ipaddr);
	else {
		jlog(L_ERROR, "ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "port", &dsd_cfg->port))
		jlog(L_DEBUG, "port: %s", dsd_cfg->port);
	else {
		jlog(L_ERROR, "port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_host", &dsd_cfg->db_host))
		jlog(L_DEBUG, "db_host: %s", dsd_cfg->db_host);
	else {
		jlog(L_ERROR, "db_host is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_user", &dsd_cfg->db_user))
		jlog(L_DEBUG, "db_user: %s", dsd_cfg->db_user);
	else {
		jlog(L_ERROR, "db_user is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_pwd", &dsd_cfg->db_pwd))
		jlog(L_DEBUG, "db_pwd: ***");
	else {
		jlog(L_ERROR, "db_pwd is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_name", &dsd_cfg->db_name))
		jlog(L_DEBUG, "db_name: %s", dsd_cfg->db_name);
	else {
		jlog(L_ERROR, "db_name is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "certificate", &dsd_cfg->certificate))
		jlog(L_DEBUG, "certificate: %s", dsd_cfg->certificate);
	else {
		jlog(L_ERROR, "certificate is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "privatekey", &dsd_cfg->privatekey))
		jlog(L_DEBUG, "privatekey: %s", dsd_cfg->privatekey);
	else {
		jlog(L_ERROR, "privatekey is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "trusted_cert", &dsd_cfg->trusted_cert))
		jlog(L_DEBUG, "trusted_cert: %s", dsd_cfg->trusted_cert);
	else {
		jlog(L_ERROR, "trusted_cert is not present !");
		return -1;
	}

	return 0;
}

void int_handler(int sig)
{
	(void)sig;
	dsd_cfg->dsd_running = 0;
}

int main(int argc, char *argv[])
{
	int opt;
	uint8_t quiet = 0;
	uint8_t daemon = 0;
	config_t cfg;
	dsd_cfg = calloc(1, sizeof(struct dsd_cfg));

	signal(SIGINT, int_handler);

	while ((opt = getopt(argc, argv, "dqvh")) != -1) {
		switch (opt) {
		case 'd':
			daemon = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'v':
			fprintf(stdout, "version: %s\n", DSDVERSION);
			return 0;
		default:
		case 'h':
                        fprintf(stdout, "\nDynVPN dsd server:\n\n"
					"-d\t\tdaemonize\n"
                                        "-q\t\tquiet mode\n"
                                        "-v\t\tshow version\n"
                                        "-h\t\tshow this help\n");
			return 0;
		}
	}

	if (!quiet && !daemon) {
		jlog_init_cb(on_log);
	}

	config_init(&cfg);

	if (parse_config(&cfg, dsd_cfg)) {
		jlog(L_ERROR, "parse_config failed");
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "krypt_init failed");
		exit(EXIT_FAILURE);
	}

	if (dao_connect(dsd_cfg)) {
		jlog(L_ERROR, "dao_connect failed");
		exit(EXIT_FAILURE);
	}

	netbus_tcp_init();
	if (netbus_init()) {
		jlog(L_ERROR, "netbus_init failed");
		exit(EXIT_FAILURE);
	}

	if (dsd_init(dsd_cfg)) {
		jlog(L_NOTICE, "dnds_init failed");
		exit(EXIT_FAILURE);
	}

	if (daemon) {
		daemonize();
	}

	while (dsd_cfg->dsd_running) {
		sleep(1);
	}

	dsd_fini();
	netbus_fini();
	config_destroy(&cfg);
	free(dsd_cfg);

	sleep(1);

	return 0;
}
