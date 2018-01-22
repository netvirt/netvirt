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

#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/tree.h>

#include <string.h>

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>
#include <event2/util.h>

#include <jansson.h>

#include <pki.h>

#include "agent.h"

#define NDB_VERSION 1

RB_HEAD(network_tree, network);

struct network_tree	 networks;
json_t			*jdb;
json_t			*jnetworks;
int			 version;
char			 ndb_path[256];

static struct network	*ndb_network_new();
static int		 ndb_save();
static int		 ndb_fullpath(const char *, char *);
static int		 network_cmp(const struct network *, const struct network *);
RB_PROTOTYPE_STATIC(network_tree, network, entry, network_cmp);

int
network_cmp(const struct network *a, const struct network *b)
{
	return strcmp(a->name, b->name);
}

#if defined(__unix__) || defined(__APPLE__)
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

#if defined(__unix__) || defined(__APPLE__)
	{
		/* Create ~/.config/netvirt/ if it doesn't exist. */
		struct	 stat st;
		char	 path[256];

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

	if (ndb_fullpath("nvagent.json", ndb_path) < 0) {
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

		if ((n = ndb_network_new()) == NULL)
			return (-1);

		if (json_unpack(jnetwork, "{s:s, s:s, s:s, s:s, s:s}", "name", &n->name, "ctlsrv_addr", &n->ctlsrv_addr,
		    "cert", &n->cert, "pvkey", &n->pvkey, "cacert", &n->cacert) < 0) {
			fprintf(stderr, "%s: json_unpack\n", __func__);
			return (-1);
		}
		n->idx = i;

		RB_INSERT(network_tree, &networks, n);
	}

	return (0);
}

void
ndb_networks(void)
{
	struct network	*n;
	printf("Networks:\n");
	RB_FOREACH(n, network_tree, &networks) {
		printf("\t[%zu] \"%s\"\n", n->idx, n->name);
	}
}

void
ndb_network_free(struct network *n)
{
	if (n == NULL)
		return;

	free(n->name);
	free(n->ctlsrv_addr);
	free(n->cert);
	free(n->pvkey);
	free(n->cacert);
	free(n);
}

struct network *
ndb_network_new()
{
	struct network	*n = NULL;

	if ((n = malloc(sizeof(struct network))) == NULL) {
		fprintf(stderr, "%s: malloc\n", __func__);
		return (NULL);
	}
	n->idx = 0;
	n->name = NULL;
	n->ctlsrv_addr = NULL;
	n->cert = NULL;
	n->pvkey = NULL;
	n->cacert = NULL;

	return (n);
}

int
ndb_network_add(struct network *netcf, const char *cert, const char *cacert)
{
	netcf->cert = strdup(cert);
	netcf->cacert = strdup(cacert);

	RB_INSERT(network_tree, &networks, netcf);
	ndb_save();

	return (0);
}

int
ndb_network_remove(const char *network_name)
{
	(void)network_name;
	return (0);
}

struct network *
ndb_network(const char *network_name)
{
	struct network	needle, *n = NULL;
	needle.name = (char *)network_name;
	if ((n = RB_FIND(network_tree, &networks, &needle)) == NULL)
		return (NULL);

	return (n);
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

		if ((json_array_append_new(jnetworks, jnetwork)) < 0) {
			fprintf(stderr, "%s: json_array_append\n", __func__);
			goto out;
		}

		if (json_object_set_new_nocheck(jnetwork, "name",
		    json_string(n->name)) < 0 ||
		    json_object_set_new_nocheck(jnetwork, "ctlsrv_addr",
		    json_string(n->ctlsrv_addr)) < 0 ||
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
ndb_prov_cb(struct evhttp_request *req, void *arg)
{
	json_t			*jmsg;
	json_error_t		 error;
	struct evbuffer         *buf;
	struct network		*netcfg = arg;
	const char		*ctlsrv_addr;
	const char		*cacert;
	const char		*cert;
	void                    *p;

	buf = evhttp_request_get_input_buffer(req);
	p = evbuffer_pullup(buf, -1);

	if ((jmsg = json_loadb(p, evbuffer_get_length(buf), 0, &error)) == NULL) {
		fprintf(stdout, "%s: json_loadb - %s\n", __func__, error.text);
		goto err;
	}

	if (json_unpack(jmsg, "{s:s, s:s, s:s}",
	    "ctlsrv_addr", &ctlsrv_addr, "cert", &cert, "cacert", &cacert) < 0) {
		fprintf(stdout, "%s: json_unpack", __func__);
		goto err;
	}

	netcfg->ctlsrv_addr = strdup(ctlsrv_addr);
	ndb_network_add(netcfg, cert, cacert);

	json_decref(jmsg);

	exit(0);
err:
	return;
}

int
ndb_provisioning(const char *provlink, const char *network_name)
{
	EVP_PKEY			*keyring = NULL;
	X509_REQ			*certreq = NULL;
	json_t				*jresp;
	digital_id_t			*nva_id = NULL;
	struct evhttp_connection	*evhttp_conn;
	struct evhttp_request		*req;
	struct evkeyvalq		 headers = TAILQ_HEAD_INITIALIZER(headers);
	struct evkeyvalq		*output_headers;
	struct evbuffer			*output_buffer;
	struct evhttp_uri		*uri;
	struct network			*netcf;
	long				 size = 0;
	const char			*version;
	const char			*provsrv_addr;
	char				*resp;
	char				*certreq_pem = NULL;
	char				*pvkey_pem = NULL;

	nva_id = pki_digital_id("",  "", "", "", "contact@dynvpn.com", "www.dynvpn.com");

	/* generate RSA public and private keys */
	keyring = pki_generate_keyring();

	/* create a certificate signing request */
	certreq = pki_certificate_request(keyring, nva_id);
	pki_free_digital_id(nva_id); // XXX that shounld't even exist

	/* write the certreq in PEM format */
	pki_write_certreq_in_mem(certreq, &certreq_pem, &size);
	X509_REQ_free(certreq);

	/* write the private key in PEM format */
	pki_write_privatekey_in_mem(keyring, &pvkey_pem, &size);
	EVP_PKEY_free(keyring);

	if ((uri = evhttp_uri_parse(provlink)) == NULL)
		return (-1);

	if ((evhttp_parse_query_str(evhttp_uri_get_query(uri), &headers)) < 0)
		return (-1);

	if ((netcf = ndb_network_new()) == NULL)
		return (-1);

	netcf->name = strdup(network_name);
	netcf->pvkey = pvkey_pem; // Steal the pointer

	if ( ((version = evhttp_find_header(&headers, "v")) == NULL) ||
	     ((provsrv_addr = evhttp_find_header(&headers, "a")) == NULL) ) {
			return (-1);
	}

	evhttp_conn = evhttp_connection_base_new(ev_base, NULL, provsrv_addr, 8080);
	req = evhttp_request_new(ndb_prov_cb, netcf);

	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Content-Type", "application/json");

	jresp = json_object();
	json_object_set_new(jresp, "csr", json_string(certreq_pem));

	json_object_set_new(jresp, "provlink", json_string(provlink));
	resp = json_dumps(jresp, 0);

	output_buffer = evhttp_request_get_output_buffer(req);
	evbuffer_add(output_buffer, resp, strlen(resp));

	char size_cl[22];
	evutil_snprintf(size_cl, sizeof(size_cl), "%d", strlen(resp));
	evhttp_add_header(output_headers, "Content-Length", size_cl);

	free(resp); // XXX could use only buffer pointer

	evhttp_make_request(evhttp_conn, req, EVHTTP_REQ_POST, "/v1/provisioning");

	evhttp_clear_headers(&headers);
	evhttp_uri_free(uri);

	json_decref(jresp);
	free(certreq_pem);
	return (0);
}

void
ndb_fini()
{

}

RB_GENERATE_STATIC(network_tree, network, entry, network_cmp);
