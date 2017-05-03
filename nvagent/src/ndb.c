/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <sys/stat.h>

#include <string.h>

#include <jansson.h>

static int	ndb_fullpath(const char *, char *);

struct network {
	char	*name;
	char	*cert;
	char	*pvkey;
	char	*cacert;
};

struct networkdb {
	int	 version;

};

#if defined(__unix__) && !defined(__APPLE__)
static int
mkfullpath(const char *fullpath)
{
	char	*p = NULL;
	char	 tmp[256];

	if (fullpath == NULL)
		return (-1);

	snprintf(tmp, sizeof(tmp),"%s",fullpath);
	if ((p = strchr(tmp, '/')) == NULL)
		return (-1);

	while ((p = strchr(p+1, '/')) != NULL) {
		*p = '\0';
		mkdir(tmp, S_IRWXU | S_IWUSR | S_IXUSR);
		*p = '/';
	}
	return (0);
}
#endif

int
ndb_fullpath(const char *file, char *fullname)
{
#ifdef _WIN32
	return snprintf(fullname, 256, "%s%s%s%s",
	    getenv("AppData"), "\\netvirt\\", "\\", file);
#else
	return snprintf(fullname, 256, "%s%s%s%s",
	    getenv("HOME"), "/.config/netvirt", "/", file);
#endif
}

int
ndb_init(void)
{
	json_t		*jdb;
	json_t		*jnetworks;
	json_t		*jnetwork;
	json_error_t	 error;
	size_t		 array_size;
	size_t		 i;
	char		 path[256];

#if defined(__unix__)
	{
		/* Create ~/.config/netvirt if it doesn't exist. */
		struct	 stat st;

		if (ndb_fullpath("", path) < 0) {
			fprintf(stderr, "%s: ndb_fullpath\n", __func__);
			exit(-1);
		}

		if (stat(path, &st) != 0) {
			mkfullpath(path);
			if (stat(path, &st) != 0) {
				fprintf(stderr, "%s: stat\n", __func__);
				exit(-1);
			}
		}
	}
#endif

	if (ndb_fullpath("nvswitch.nv", path) < 0) {
		fprintf(stderr, "%s: ndb_fullpath\n", __func__);
		exit(-1);
	}

	jdb = json_load_file(path, 0, &error);

	struct network n;
	struct networkdb ndb;

	json_unpack(jdb, "{s:i}", "version", &ndb.version);
	printf("version %d\n", ndb.version);

	jnetworks = json_object_get(jdb, "networks");

	array_size = json_array_size(jnetworks);

	for (i = 0; i < array_size; i++) {

		jnetwork = json_array_get(jnetworks, i);

		json_unpack(jnetwork, "{s:s, s:s, s:s, s:s}", "name", &n.name,
		    "cert", &n.cert, "pvkey", &n.pvkey, "cacert", &n.cacert);

		printf("cert:\n%s\n", n.cert);
	}


	return (0);
}

void
ndb_fini()
{

}
