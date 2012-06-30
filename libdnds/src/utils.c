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

#include "journal.h"
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

extern char *x_strtok(char **a, char **z, char delim)
{
	char *r = *a;
	if (*a == NULL)
		return r;

	*z = strchr(*a, delim);
	if (*z == NULL) {
		*a = NULL;
		return r;
	}

	**z = '\0';
	*a = ++(*z);

	return r;
}

int swap_context(char *str, const unsigned int context)
{
        char *s;
        s = strchr(str, '@');

        if (s == NULL || context == 0)
                return -1;

        s++;
        snprintf(s, sizeof(context), "%u", context);

        return 0;
}

char *x509_get_cn(char *path)
{
	FILE *f;
	size_t n;
	unsigned char *buf;

	char *needle;
	char *end;
	char *cn;

	size_t ret;

	f = fopen(path, "rb");
	if (f == NULL) {
		jlog(L_NOTICE, "utils]> fopen() no such file : %s :: %s %i \n", path, __FILE__, __LINE__);
		return NULL;
	}

	ret = fseek(f, 0, SEEK_END);
	if (ret == -1) {
		jlog(L_NOTICE, "utils]> fseek() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	n = (size_t) ftell(f);

	ret = fseek(f, 0, SEEK_SET);
	if (ret == -1) {
		jlog(L_NOTICE, "utils]> fseek() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	buf = (unsigned char *) malloc(n+1);
	if (buf == NULL) {
		jlog(L_NOTICE, "utils]> malloc() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	ret = fread(buf, 1, n, f);
	if (ret != n) {
		fclose(f);
		free(buf);
		jlog(L_NOTICE, "utils]> fread() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	buf[n] = '\0';

	needle = strstr((const char *)buf, "Subject:");
	if (needle == NULL) {
		jlog(L_NOTICE, "utils]> strstr() \"Subject\" substring not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}

	needle = strstr(needle, "CN=");
	if (needle == NULL) {
		jlog(L_NOTICE, "utils]> strstr() \"CN=\" substring not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}

	needle += strlen("CN=");
	if (needle == NULL) {
		jlog(L_NOTICE, "utils]> strstr() \"CN=\" substring not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}


	end = strchr(needle, '/');
	if (end == NULL) {
		jlog(L_NOTICE, "utils]> strchr() \"/\" character not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}

	*end = '\0';

	cn = strdup(needle);
	if (cn == NULL) {
		jlog(L_NOTICE, "utils]> strdup() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	if (buf)
		free(buf);

	if (cn == NULL)
		return NULL;

	return cn;
}
