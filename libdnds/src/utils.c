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


extern int bv_set(const unsigned int dbit,
			uint8_t *vector,
			const unsigned int VSIZE)
{
     if (dbit > 0 && dbit < VSIZE) {
		vector[dbit >> 3] |= 1 << (dbit&7);
		return 0;
	}

	JOURNAL_NOTICE("utils]> The dbit `%i` is out of the vector `%i` \
			:: %s:%i\n", dbit, VSIZE, __FILE__, __LINE__);
	return -1;
}

extern int bv_unset(const unsigned int dbit,
			uint8_t *vector,
			const unsigned int VSIZE)
{
	if (dbit > 0 && dbit < VSIZE) {
		vector[dbit >> 3] &= ~(1 << (dbit&7));
		return 0;
	}

	JOURNAL_NOTICE("utils]> The dbit `%i` is out of the vector `%i` \
			:: %s:%i\n", dbit, VSIZE, __FILE__, __LINE__);
	return -1;
}

extern int bv_test(const unsigned int dbit,
			uint8_t *vector,
			const unsigned int VSIZE)
{
	if (dbit > 0 && dbit < VSIZE)
		return vector[dbit >> 3] >> (dbit&7) & 1;

	JOURNAL_NOTICE("utils]> The dbit `%i` is out of the vector `%i` \
			:: %s:%i\n", dbit, VSIZE, __FILE__, __LINE__);
	return -1;
}

static void set_bit(uint8_t bitmap[], size_t bit)
{
	bitmap[bit/8] |= (1 << (bit % 8));
}

static void reset_bit(uint8_t bitmap[], size_t bit)
{
	bitmap[bit/8] &= ~(1 << (bit % 8));
}

static int get_bit(const uint8_t bitmap[], size_t bit)
{
	return (bitmap[bit/8] >> (bit % 8)) & 1;
}

extern int alloc_bitmap(size_t bits, uint8_t **bitmap)
{
	int byte_size = (bits+7)/8;

	*bitmap = calloc(byte_size, sizeof(uint8_t));

	return *bitmap != 0;
}

extern int allocate_bit(uint8_t bitmap[], size_t bits, uint32_t *bit)
{
	int i, j, byte_size;

	byte_size = bits/8;

	/* byte */
	for (i = 0; (i < byte_size) && (bitmap[i] == 0xff); i++);

	if (i == byte_size)
		return -1;

	/* bit */
	for (j = 0; get_bit( bitmap+i, j); j++);

	*bit = i * 8 + j;
	set_bit(bitmap, *bit);

	return 0;
}

extern int free_bit(uint8_t bitmap[], size_t bits, size_t bit)
{
	if (bit < bits) {
		reset_bit(bitmap, bit);
		return 0;
	}

	return -1;
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
		JOURNAL_NOTICE("utils]> fopen() no such file : %s :: %s %i \n", path, __FILE__, __LINE__);
		return NULL;
	}

	ret = fseek(f, 0, SEEK_END);
	if (ret == -1) {
		JOURNAL_NOTICE("utils]> fseek() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	n = (size_t) ftell(f);

	ret = fseek(f, 0, SEEK_SET);
	if (ret == -1) {
		JOURNAL_NOTICE("utils]> fseek() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	buf = (unsigned char *) malloc(n+1);
	if (buf == NULL) {
		JOURNAL_NOTICE("utils]> malloc() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	ret = fread(buf, 1, n, f);
	if (ret != n) {
		fclose(f);
		free(buf);
		JOURNAL_NOTICE("utils]> fread() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	buf[n] = '\0';

	needle = strstr((const char *)buf, "Subject:");
	if (needle == NULL) {
		JOURNAL_NOTICE("utils]> strstr() \"Subject\" substring not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}

	needle = strstr(needle, "CN=");
	if (needle == NULL) {
		JOURNAL_NOTICE("utils]> strstr() \"CN=\" substring not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}

	needle += strlen("CN=");
	if (needle == NULL) {
		JOURNAL_NOTICE("utils]> strstr() \"CN=\" substring not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}


	end = strchr(needle, '/');
	if (end == NULL) {
		JOURNAL_NOTICE("utils]> strchr() \"/\" character not found :: %s:%i\n", __FILE__, __LINE__);
		return NULL;
	}

	*end = '\0';

	cn = strdup(needle);
	if (cn == NULL) {
		JOURNAL_NOTICE("utils]> strdup() %s :: %s:%i\n", strerror(errno), __FILE__, __LINE__);
		return NULL;
	}

	if (buf)
		free(buf);

	if (cn == NULL)
		return NULL;

	return cn;
}
