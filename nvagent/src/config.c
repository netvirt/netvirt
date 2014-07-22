/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#if defined(__unix__)
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <libconfig.h>
#include <stdlib.h>

#include <logger.h>
#include "agent.h"

static struct agent_cfg *agent_cfg;

char *agent_config_get_fullname(const char *file)
{
#ifdef _WIN32
	char fullname[256];
	snprintf(fullname, sizeof(fullname), "%s%s%s", getenv("AppData"), "\\netvirt\\", file);
	return strdup(fullname);
#elif __APPLE__
	return strdup(file);
#else
	char fullname[256];
	snprintf(fullname, sizeof(fullname), "%s%s%s", getenv("HOME"), "/.netvirt/", file);
	return strdup(fullname);
#endif
}

int agent_config_toggle_auto_connect(int status)
{
	config_setting_t *root, *setting;
	config_t cfg;

	config_init(&cfg);
	root = config_root_setting(&cfg);

	/* Read the file. If there is an error, report it and exit. */
        if (!config_read_file(&cfg, agent_cfg->agent_conf)) {
                fprintf(stderr, "Can't open %s\n", agent_cfg->agent_conf);
		return -1;
        }

	setting = config_setting_get_member(root, "auto_connect");
	if (setting == NULL) {
                setting = config_setting_add(root, "auto_connect", CONFIG_TYPE_BOOL);
	}
	config_setting_set_bool(setting, status);

	config_write_file(&cfg, agent_cfg->agent_conf);
	config_setting_set_bool(setting, status);
	config_destroy(&cfg);

	return 0;
}

int agent_config_init(struct agent_cfg *_agent_cfg)
{
	int ret = 0;
	uint8_t default_conf = 0;
	config_t cfg;
	config_init(&cfg);

	agent_cfg = _agent_cfg;

	jlog_init_cb(agent_cfg->ev.on_log);
	jlog(L_NOTICE, "version: %s", DNCVERSION);

	agent_cfg->agent_conf = agent_config_get_fullname("nvagent.conf");
	agent_cfg->ip_conf = agent_config_get_fullname("nvagent.ip");

	/* Read the file. If there is an error, use default configuration */
        if (config_read_file(&cfg, agent_cfg->agent_conf) == CONFIG_FALSE) {
		default_conf = 1;
        }

#if defined(__unix__) && !defined(__APPLE__)
	/* Create ~/.netvirt if it doesn't exist. */
	char *path = agent_config_get_fullname("");
	struct stat st;
	if (stat(path, &st) != 0) {
		ret = mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR);
		if (ret == -1) {
			free(path);
			return -1;
		}
	}
	free(path);
#endif
	/* Create CONFPATH/nvagent.conf if it doesn't exist. */
	if (default_conf == 1) {
		if (config_write_file(&cfg, agent_cfg->agent_conf) == CONFIG_FALSE) {
			jlog(L_ERROR, "Unable to create file %s, might be a permission problem.", agent_cfg->agent_conf);
			return -1;
		}
	}

	jlog(L_NOTICE, "conf: %s", agent_cfg->agent_conf);

	agent_cfg->certificate = agent_config_get_fullname("certificate.pem");
	agent_cfg->privatekey = agent_config_get_fullname("privatekey.pem");
	agent_cfg->trusted_cert = agent_config_get_fullname("trusted_cert.pem");

	if (config_lookup_string(&cfg, "log_file", &agent_cfg->log_file)) {
		jlog_init_file(agent_cfg->log_file);
	}

        if (agent_cfg->server_address == NULL &&
		(default_conf ||
		!config_lookup_string(&cfg, "server_address", &agent_cfg->server_address))) {
			agent_cfg->server_address = strdup("bhs1.dynvpn.com");
	}
	jlog(L_DEBUG, "server_address = \"%s\";", agent_cfg->server_address);

        if (default_conf || !config_lookup_string(&cfg, "server_port", &agent_cfg->server_port)) {
		agent_cfg->server_port = strdup("9090");
	}
	jlog(L_DEBUG, "server_port = \"%s\";", agent_cfg->server_port);

	if (default_conf || !config_lookup_bool(&cfg, "auto_connect", &agent_cfg->auto_connect) ) {
		agent_cfg->auto_connect = 0;
	}

	return 0;
}
