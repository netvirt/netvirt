/*
 * utils.c: Utility functions API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "logger.h"
#include "utils.h"

/* TODO
 * almost everything here is legacy code,
 * we should probably remove this file
 */

extern int daemonize()
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

extern char *trim(char *str)
{
	if (str == NULL)
		return NULL;

	char *a, *z;
	a = str;
	while (*a == ' ') a++;

	z = a + strlen(a);
	if (z == NULL)
		return NULL;

	while (*--z == ' ' && (z > a));
	*++z = '\0';

	return a;
}
