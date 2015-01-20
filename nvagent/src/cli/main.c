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

#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logger.h>

#include "../agent.h"
#include "../config.h"

static struct agent_cfg *agent_cfg = NULL;
void int_handler(int sig)
{
	(void)sig;
	agent_cfg->agent_running = 0;
}

void on_log(const char *logline)
{
	fprintf(stdout, "%s", logline);
}

int main(int argc, char *argv[])
{
	int opt;
	agent_cfg = calloc(1, sizeof(struct agent_cfg));

	signal(SIGINT, int_handler);

	while ((opt = getopt(argc, argv, "p:s:vhk:")) != -1) {
		switch (opt) {
		case 'k':
			agent_cfg->prov_code = strdup(optarg);
			break;
		case 's':
			agent_cfg->server_address = strdup(optarg);
			break;
		case 'p':
			agent_cfg->profile = strdup(optarg);
			break;
		case 'v':
			fprintf(stdout, "netvirt-agent %s\n", NVAGENT_VERSION);
			return 0;
		case 'h':
			fprintf(stdout, "netvirt-agent:\n"
					"-k key\t\tauto provisioning\n"
					"-s hostname\tserver address\n"
					"-p name\t\tselect profile\n"
					"-v\t\tshow version\n"
					"-h\t\tshow this help\n");
			return 0;
		default:
			return 0;
		}
	}

	agent_cfg->ev.on_log = on_log;

	if (agent_config_init(agent_cfg)) {
		jlog(L_ERROR, "agent_config_init failed");
		exit(EXIT_FAILURE);
	}

	jlog(L_NOTICE, "connecting...");

	if (agent_init(agent_cfg)) {
		jlog(L_ERROR, "agent_init failed");
		exit(EXIT_FAILURE);
	}

	agent_cfg->agent_running = 1;

	while(agent_cfg->agent_running) {
		sleep(1);
	}

	agent_fini();

	agent_config_destroy(agent_cfg);
	free(agent_cfg);

	return 0;
}

