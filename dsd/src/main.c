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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include <libconfig.h>

#include <dnds.h>
#include <logger.h>
#include <netbus.h>

#include "dao.h"
#include "dsd.h"

#define CONFIG_FILE "/etc/dnds/dsd.conf"

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
		jlog(L_ERROR, "dsd]> Can't open %s", CONFIG_FILE);
		return -1;
	}

	if (config_lookup_string(cfg, "ipaddr", &dsd_cfg->ipaddr))
		jlog(L_DEBUG, "dsd]> ipaddr: %s", dsd_cfg->ipaddr);
	else {
		jlog(L_ERROR, "dsd]> ipaddr is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "port", &dsd_cfg->port))
		jlog(L_DEBUG, "dsd]> port: %s", dsd_cfg->port);
	else {
		jlog(L_ERROR, "dsd]> port is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_host", &dsd_cfg->db_host))
		jlog(L_DEBUG, "dsd]> db_host: %s", dsd_cfg->db_host);
	else {
		jlog(L_ERROR, "dsd]> db_host is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_user", &dsd_cfg->db_user))
		jlog(L_DEBUG, "dsd]> db_user: %s", dsd_cfg->db_user);
	else {
		jlog(L_ERROR, "dsd]> db_user is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_pwd", &dsd_cfg->db_pwd))
		jlog(L_DEBUG, "dsd]> db_pwd: %s", dsd_cfg->db_pwd);
	else {
		jlog(L_ERROR, "dsd]> db_pwd is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "db_name", &dsd_cfg->db_name))
		jlog(L_DEBUG, "dsd]> db_name: %s", dsd_cfg->db_name);
	else {
		jlog(L_ERROR, "dsd]> db_name is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "certificate", &dsd_cfg->certificate))
		jlog(L_DEBUG, "dsd]> certificate: %s", dsd_cfg->certificate);
	else {
		jlog(L_ERROR, "dsd]> certificate is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "privatekey", &dsd_cfg->privatekey))
		jlog(L_DEBUG, "dsd]> privatekey: %s", dsd_cfg->privatekey);
	else {
		jlog(L_ERROR, "dsd]> privatekey is not present !");
		return -1;
	}

	if (config_lookup_string(cfg, "trusted_cert", &dsd_cfg->trusted_cert))
		jlog(L_DEBUG, "dsd]> trusted_cert: %s", dsd_cfg->trusted_cert);
	else {
		jlog(L_ERROR, "dsd]> trusted_cert is not present !");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int opt, D_FLAG = 0;
	struct dsd_cfg *dsd_cfg;
	config_t cfg;

	if (getuid() != 0) {
		jlog(L_NOTICE, "%s must be run as root", argv[0]);
		exit(EXIT_FAILURE);
	}

	dsd_cfg = calloc(1, sizeof(struct dsd_cfg));

	while ((opt = getopt(argc, argv, "dv")) != -1) {
		switch (opt) {
		case 'd':
			D_FLAG = 1;
			break;
		case 'v':
			printf("beta version\n");
			exit(EXIT_SUCCESS);
		default:
			printf("-d , -v\n");
			jlog(L_NOTICE, "dsd]> getopt failed :: %s:%i", __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	}

	config_init(&cfg);

	if (parse_config(&cfg, dsd_cfg)) {
		jlog(L_ERROR, "dsd]> parse_config failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (krypt_init()) {
		jlog(L_ERROR, "dsd]> krypt_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (dao_connect(dsd_cfg)) {
		jlog(L_ERROR, "dsd]> dao_connect failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	netbus_tcp_init();
	if (netbus_init()) {
		jlog(L_ERROR, "dsd]> netbus_init failed:: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (dsd_init(dsd_cfg)) {
		jlog(L_NOTICE, "dsd]> dnds_init failed :: %s:%i\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (D_FLAG) {
		daemonize();
	}

	while(1) { sleep(1); }

	return 0;
}
