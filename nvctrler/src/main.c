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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ctrler.h"
#include "dao.h"
#include "pki.h"

#define CONFIG_FILE "/etc/netvirt/nvctrler.conf"

static struct ctrler_cfg *ctrler_cfg;
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

int main(int argc, char *argv[])
{
	int		 opt;
	uint8_t		 daemon = 0;

	ctrler_cfg = calloc(1, sizeof(struct ctrler_cfg));

	while ((opt = getopt(argc, argv, "bdqvh")) != -1) {
		switch (opt) {
		case 'b':
			pki_bootstrap_certs();
			return 0;
		case 'd':
			daemon = 1;
			break;
		case 'v':
			fprintf(stdout, "netvirt-ctrler %s\n", NVCTRLER_VERSION);
			return 0;
		default:
		case 'h':
                        fprintf(stdout, "netvirt-ctrler:\n"
					"-b\t\tbootstrap certificates\n"
					"-d\t\tdaemonize\n"
                                        "-v\t\tshow version\n"
                                        "-h\t\tshow this help\n");
			return 0;
		}
	}
/*
	if (dao_connect(ctrler_cfg)) {
		//jlog(L_ERROR, "dao_connect failed");
		exit(EXIT_FAILURE);
	}
*/
	if (daemon) {
		daemonize();
	}

//	ctrler_init(ctrler_cfg);
	//jlog(L_NOTICE, "good bye\n");

	ctrler_fini();
	dao_disconnect();

	return 0;
}
