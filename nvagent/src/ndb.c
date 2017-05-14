/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <sys/stat.h>
#include <sys/tree.h>

#include <string.h>

#include <jansson.h>

#include "agent.h"

#define NDB_VERSION 1

struct network {
	RB_ENTRY(network)	 entry;
	size_t			 idx;
	char			*name;
	char			*cert;
	char			*pvkey;
	char			*cacert;
};

RB_HEAD(network_tree, network);

struct network_tree	 networks;
json_t			*jdb;
json_t			*jnetworks;
int			 version;
char			 ndb_path[256];

static int	ndb_save();
static int	ndb_fullpath(const char *, char *);
static int	network_cmp(const struct network *, const struct network *);
RB_PROTOTYPE_STATIC(network_tree, network, entry, network_cmp);

int
network_cmp(const struct network *a, const struct network *b)
{
	printf("a: %s\n", a->name);
	printf("b: %s\n", b->name);
	return strcmp(a->name, b->name);
}

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
	json_t		*jnetwork;
	json_error_t	 error;
	struct network	 *n;
	int		 version;
	size_t		 array_size;
	size_t		 i;
	char		 path[256];

#if defined(__unix__)
	{
		/* Create ~/.config/netvirt/ if it doesn't exist. */
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

	if (ndb_fullpath("nvswitch.nv", ndb_path) < 0) {
		fprintf(stderr, "%s: ndb_fullpath\n", __func__);
		exit(-1);
	}

	if ((jdb = json_load_file(ndb_path, 0, &error)) == NULL)
		return (0);

	if ((json_unpack(jdb, "{s:i}", "version", &version)) == -1) {
		fprintf(stderr, "%s: json_unpack\n", __func__);
		return (-1);
	}

	if ((jnetworks = json_object_get(jdb, "networks")) == NULL)
		return (0);

	array_size = json_array_size(jnetworks);
	for (i = 0; i < array_size; i++) {

		if ((jnetwork = json_array_get(jnetworks, i)) == NULL)
			continue;

		if ((n = malloc(sizeof(struct network))) == NULL)
			return (-1);

		json_unpack(jnetwork, "{s:s, s:s, s:s, s:s}", "name", &n->name,
		    "cert", &n->cert, "pvkey", &n->pvkey, "cacert", &n->cacert);
		n->idx = i;

		RB_INSERT(network_tree, &networks, n);
	}

	return (0);
}

void
ndb_networks(void)
{
	struct network	*n;
	printf("networks:\n");
	RB_FOREACH(n, network_tree, &networks) {
		printf("\tname \"%s\"\n", n->name);
	}
}


int
ndb_network_add(const char *network_name, const char *pvkey,
    const char *cert, const char *cacert)
{

	printf("add new network\n");
	struct network	*n;

	if ((n = malloc(sizeof(struct network))) == NULL) {
		fprintf(stderr, "%s: malloc\n", __func__);
		return -1;
	}

	n->name = strdup(network_name);
	n->pvkey = strdup(pvkey);
	n->cert = strdup(cert);
	n->cacert = strdup(cacert);

	RB_INSERT(network_tree, &networks, n);

	ndb_save();

	return (0);
}

int
ndb_network_remove(const char *network_name)
{
	return (0);
}


int
ndb_network(const char *network_name, char **pvkey, char **cert, char **cacert)
{
	struct network	needle, *n;
	needle.name = (char *)network_name;
	if ((n = RB_FIND(network_tree, &networks, &needle)) == NULL)
		return (-1);

	*pvkey = n->pvkey;
	*cert = n->cert;
	*cacert = n->cacert;

	return (0);
}

int
ndb_save()
{
	json_t		*jdb = NULL;
	json_t		*jnetworks = NULL;
	json_t		*jnetwork = NULL;
	struct network	*n;
	int		 ret = -1;

	if ((jdb = json_object()) == NULL) {
		fprintf(stderr, "%s: json_object\n", __func__);
		goto out;
	}

	if ((jnetworks = json_array()) == NULL) {
		fprintf(stderr, "%s: json_array\n", __func__);
		goto out;
	}

	if (json_object_set_new_nocheck(jdb, "version",
	    json_integer(NDB_VERSION)) < 0 ||
	    json_object_set_new_nocheck(jdb, "networks", jnetworks) < 0) {
		fprintf(stderr, "%s: json_object_set_new_nocheck\n", __func__);
		goto out;
	}

	RB_FOREACH(n, network_tree, &networks) {

		if ((jnetwork = json_object()) == NULL) {
			fprintf(stderr, "%s: json_object\n", __func__);
			goto out;
		}

		if ((json_array_append(jnetworks, jnetwork)) < 0) {
			fprintf(stderr, "%s: json_array_append\n", __func__);
			goto out;
		}

		if (json_object_set_new_nocheck(jnetwork, "name",
		    json_string(n->name)) < 0 ||
		    json_object_set_new_nocheck(jnetwork, "pvkey",
		    json_string(n->pvkey)) < 0 ||
		    json_object_set_new_nocheck(jnetwork, "cert",
		    json_string(n->cert)) < 0 ||
		    json_object_set_new_nocheck(jnetwork, "cacert",
		    json_string(n->cacert)) < 0) {
			fprintf(stderr, "%s: json_object_set_new_nocheck\n",
			    __func__);
				goto out;
		}
	}

	if (json_dump_file(jdb, ndb_path, JSON_INDENT(2)) < 0) {
		fprintf(stderr, "%s: json_dump_file\n", __func__);
		goto out;
	}

	ret = 0;

out:
	json_decref(jdb);

	return (ret);
}

void
ndb_fini()
{

}

RB_GENERATE_STATIC(network_tree, network, entry, network_cmp);
