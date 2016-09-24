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

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>

#include "ctrler.h"
#include "dao.h"
#include "pki.h"

#define CONFIG_FILE "/etc/netvirt/nvctrler.conf"

int main(int argc, char *argv[])
{
	json_t		*config;
	json_error_t	 error;
	const char	*dbname;
	const char	*dbuser;
	const char	*dbpwd;
	const char	*dbhost;

	if ((config = json_load_file(CONFIG_FILE, 0, &error)) == NULL)
		errx(1, "json_load_file: line: %d - %s",
		    error.line, error.text);

	if (json_unpack(config, "{s:s}", "dbname", &dbname) < 0)
		errx(1, "%s:%d", "dbname not found in config", __LINE__);

	if (json_unpack(config, "{s:s}", "dbuser", &dbuser) < 0)
		errx(1, "%s:%d", "dbuser not found in config", __LINE__);

	if (json_unpack(config, "{s:s}", "dbpwd", &dbpwd) < 0)
		errx(1, "%s:%d", "dbpwd not found in config", __LINE__);

	if (json_unpack(config, "{s:s}", "dbhost", &dbhost) < 0)
		errx(1, "%s:%d", "dbhost not found in config", __LINE__);

	if (dao_init(dbname, dbuser, dbpwd, dbhost) < 0)
		errx(1, "dao_init");

	if (controller_init(config) < 0)
		errx(1, "controller_init");

	warnx("now off");

	controller_fini();
	dao_fini();

	return 0;
}
