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
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logger.h>
#include "../config.h"
#include "../dnc.h"

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

int main(int argc, char *argv[])
{
	int opt;
	char daemon = 0;
	struct dnc_cfg *dnc_cfg = NULL;
	dnc_cfg = calloc(1, sizeof(struct dnc_cfg));

	while ((opt = getopt(argc, argv, "dhp:")) != -1) {
		switch (opt) {
		case 'd':
			daemon = 1;
			break;
		case 'p':
			jlog(L_DEBUG, "dnc]> provisioning code: %s", optarg);
			dnc_cfg->prov_code = strdup(optarg);
			break;
		case 'h':
			jlog(L_NOTICE, "\nDynVPN client:\n\n"
					"-p KEY\t\tclient provisioning\n"
					"-d\t\trun background\n"
					"-h\t\tshow this help\n");
			return 0;
		default:
			return 0;
		}
	}

#ifndef _WIN32
	if (getuid() != 0) {
		jlog(L_ERROR, "dnc]> You must be root !");
		return -1;
	}
#endif
	if (daemon)
		daemonize();

	if (dnc_config_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_config_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	jlog(L_NOTICE, "dnc]> connecting...");

	if (dnc_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	while(1) { sleep(1); }

	return 0;
}

