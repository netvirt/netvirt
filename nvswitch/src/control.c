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
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <jansson.h>

#include "vnetwork.h"
#include "control.h"

static struct event_base		*base;
static struct bufferevent		*bufev_sock;
static struct switch_cfg		*cfg;
static passport_t			*passport;
int					 control_initialized;

static int new_peer();
static int del_node(json_t *);
static int del_network(json_t *);
static int listall_node(json_t *);
static int listall_network(json_t *);
static void sighandler(evutil_socket_t, short, void *);
static int dispatch_op(json_t *);
static void on_read_cb(struct bufferevent *, void *);
static void on_event_cb(struct bufferevent *, short, void *);
static DH *get_dh_1024();
static SSL_CTX *evssl_init();

int
del_node(json_t *jmsg)
{
	char		*network_uuid;
	char		*uuid;
	json_t		*node;
	struct session	*session;
	struct vnetwork	*vnet;

	if ((node = json_object_get(jmsg, "node")) == NULL) {
		warn("json_object_get failed");
		return -1;
	}

	if (json_unpack(node, "{s:s}", "uuid", &uuid) == -1) {
		warn("json_unpack failed");
		return -1;
	}

	if (json_unpack(node, "{s:s}", "networkuuid", &network_uuid) == -1) {
		warn("json_unpack failed");
		return -1;
	}

	if ((vnet = vnetwork_lookup(network_uuid)) == NULL) {
		warn("context_lookup failed");
		return -1;
	}

	/* remove the node from the access table */
	ctable_erase(vnet->atable, uuid);

#if 0
	/* if the node is connected, mark it to be purged */
	if ((session = ctable_find(vnet->ctable, uuid)) != NULL) {
//		session->state = SESSION_STATE_PURGE;
	}
#endif

	return 0;
}

int
del_network(json_t *jmsg)
{
	char		*network_uuid;
	json_t		*network;
	struct vnetwork	*vnet;
	struct session	*session_list;

	if ((network = json_object_get(jmsg, "network")) == NULL) {
		warn("json_object_get failed");
		return -1;
	}

	if (json_unpack(network, "{s:s}", "networkuuid", &network_uuid) == -1) {
		warn("json_unpack failed");
		return -1;
	}

	if ((vnet = vnetwork_disable(network_uuid)) == NULL) {
		warn("context_disable failed");
		return -1;
	}

#if 0
	session_list = vnet->session_list;
	while (session_list != NULL) {
	//	session_list->state = SESSION_STATE_PURGE;
		session_list->vnetwork = NULL;
		session_list = session_list->next;
	}
#endif
	vnetwork_free(vnet);

	return 0;
}

int
listall_node(json_t *jmsg)
{
	char		*uuid;
	char		*network_uuid;
	char		*response;
	size_t		 array_size;
	size_t		 i;
static	size_t		 total = 1;
	json_t		*js_nodes;
	json_t		*node;
	struct vnetwork	*vnet;

	if ((js_nodes = json_object_get(jmsg, "nodes")) == NULL) {
		warn("json_object_get failed");
		return -1;
	}

	if ((array_size = json_array_size(js_nodes)) == 0) {
		warn("json_array_size failed");
		return -1;
	}

	for (i = 0; i < array_size; i++) {

		if ((node = json_array_get(js_nodes, i)) == NULL) {
			warn("json_array_get failed");
			return -1;
		}

		if (json_unpack(node, "{s:s}", "uuid", &uuid) == -1 ||
		    json_unpack(node, "{s:s}", "networkuuid", &network_uuid) == -1) {
			warn("NULL parameter");
			return -1;
		}

		if ((vnet = vnetwork_lookup(network_uuid)) != NULL) {
			//ctable_insert(vnet->atable, uuid, vnet->access_session);
		}
	}

	if ((json_unpack(jmsg, "{s:s}", "response", &response)) == -1) {
		warn("json_unpack failed");
		return -1;
	}

	if (strcmp(response, "success") == 0) {
		warn("fetched %d node", total);
		return 0;
	}

	total++;
	return 1;
}

int
listall_network(json_t *jmsg)
{
	char	*network_id;
	char	*network_uuid;
	char	*subnet;
	char	*netmask;
	char	*cert;
	char	*pkey;
	char	*tcert;
	char	*response;
	size_t	 i;
	size_t	 array_size;
static	size_t	 total = 1;
	json_t	*js_networks;
	json_t	*elm;

	if ((json_unpack(jmsg, "{s:s}", "response", &response)) == -1) {
		warn("json_unpack failed");
		return -1;
	}

	if ((js_networks = json_object_get(jmsg, "networks")) == NULL) {
		warn("json_object_get failed");
		return -1;
	}

	if ((array_size = json_array_size(js_networks)) == 0) {
		warn("json_array_size failed");
		return -1;
	}

	for (i = 0; i < array_size; i++) {

		if ((elm = json_array_get(js_networks, i)) == NULL) {
			warn("json_array_get failed");
			return -1;
		}

		json_unpack(elm, "{s:s}", "id", &network_id);

		if (json_unpack(elm, "{s:s}", "uuid", &network_uuid) == -1 ||
		    json_unpack(elm, "{s:s}", "network", &subnet) == -1 ||
		    json_unpack(elm, "{s:s}", "netmask", &netmask) == -1 ||
		    json_unpack(elm, "{s:s}", "cert", &cert) == -1 ||
		    json_unpack(elm, "{s:s}", "pkey", &pkey) == -1 ||
		    json_unpack(elm, "{s:s}", "tcert", &tcert) == -1) {
			warn("NULL parameter");
			return -1;
		}
		vnetwork_create(network_id?network_id:"", network_uuid, subnet, netmask, cert, pkey, tcert);
	}

	warn("fetched %d network", total);
	if (strcmp(response, "success") == 0) {
		warn("fetched %d network", total);
		return 0;
	}

	total++;
	return 1;
}

int
query_list_node()
{
	warn("query list node");

	char	*query_str = NULL;
	json_t	*query = NULL;

	if ((query = json_object()) == NULL) {
		warn("json_object failed");
		goto error;
	}

	if (json_object_set_new(query, "tid", json_string("tid")) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if (json_object_set_new(query, "action", json_string("listall-node")) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		warn("json_dumps failed");
		goto error;
	}

	if (bufferevent_write(bufev_sock, query_str, strlen(query_str)) == -1) {
		warn("bufferevent_write failed");
		goto error;
	}

	if (bufferevent_write(bufev_sock, "\n", strlen("\n")) == -1) {
		warn("bufferevent_write failed");
		goto error;
	}

	json_decref(query);
	free(query_str);
	return 0;

error:
	json_decref(query);
	free(query_str);
	return -1;
}

int
update_node_status(char *status, char *local_ipaddr, char *uuid, char *network_uuid)
{
	warn("update node status");

	char	*query_str = NULL;
	json_t	*query = NULL;
	json_t	*node = NULL;

	if ((query = json_object()) == NULL) {
		warn("json_object failed");
		goto error;
	}

	if ((json_object_set_new(query, "action", json_string("update-node-status"))) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((node = json_object()) == NULL) {
		warn("json_object failed");
		goto error;
	}

	if ((json_object_set_new(query, "node", node)) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((json_object_set_new(node, "status", json_string(status))) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((json_object_set_new(node, "local-ipaddr", json_string(local_ipaddr))) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((json_object_set_new(node, "uuid", json_string(uuid))) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((json_object_set_new(node, "networkuuid", json_string(network_uuid))) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		warn("json_dumps failed");
		goto error;
	}

	json_decref(query);
	free(query_str);
	return 0;

error:
	json_decref(query);
	free(query_str);
	return -1;
}

int
query_list_network()
{
	warn("list network");

	char	*query_str = NULL;
	json_t	*query = NULL;

	if ((query = json_object()) == NULL) {
		warn("json_object failed");
		goto error;
	}

	if (json_object_set_new(query, "action", json_string("listall-network")) == -1) {
		warn("json_object_set_new failed");
		goto error;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		warn("json_dumps failed");
		goto error;
	}

	if (bufferevent_write(bufev_sock, query_str, strlen(query_str)) == -1) {
		warn("bufferevent_write failed");
		goto error;
	}

	if (bufferevent_write(bufev_sock, "\n", strlen("\n")) == -1) {
		warn("bufferevent_write failed");
		goto error;
	}

	json_decref(query);
	free(query_str);
	return 0;

error:
	json_decref(query);
	free(query_str);
	return -1;
}

void
sighandler(evutil_socket_t sk, short t, void *ptr)
{
	struct event_base	*ev_base;
	warn("sighandler!");

	ev_base = (struct event_base *)ptr;
	event_base_loopbreak(ev_base);
}

int
dispatch_op(json_t *jmsg)
{
	char	*dump;
	char	*action;
	int	 ret = 0;
/*
	dump = json_dumps(jmsg, 0);
	free(dump);
*/
	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1)
		return -1;

	if (strcmp(action, "listall-network") == 0) {
		if ((ret = listall_network(jmsg)) == 0) {
			/* all network are now fetched */
			if (control_initialized == 0) {
				warn("networks initalized");
				ret = query_list_node(jmsg);
			}
		}
	} else if (strcmp(action, "listall-node") == 0) {
		if ((ret = listall_node(jmsg)) == 0) {
			if (control_initialized == 0) {
				control_initialized = 1;
				warn("nodes initialized");
			}
		}
	} else if (strcmp(action, "del-network") == 0) {
		ret = del_network(jmsg);
	} else if (strcmp(action, "del-node") == 0) {
		ret = del_node(jmsg);
	}

	return ret;
}

void
on_read_cb(struct bufferevent *bev, void *arg)
{
	char			*str = NULL;
	size_t			n_read_out;
	json_error_t		error;
	json_t			*jmsg = NULL;

	while (evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
		if ((str = evbuffer_readln(bufferevent_get_input(bev),
		    &n_read_out, EVBUFFER_EOL_LF)) == NULL) {
			return;
		}
	//	printf("str: %d <> %s\n\n\n", strlen(str), str);
		if ((jmsg = json_loadb(str, n_read_out, 0, &error)) == NULL) {
			warn("json_loadb: %s", error.text);
			bufferevent_free(bufev_sock);
			return;
		}

		free(str);
		dispatch_op(jmsg);
		json_decref(jmsg);
	}
}

void
on_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	new_peer();
}

void
on_event_cb(struct bufferevent *bufev_sock, short events, void *arg)
{
	unsigned long	 e = 0;
	struct event	*ev;
	struct timeval	 tv = {1, 0};

	if (events & BEV_EVENT_CONNECTED) {
		warn("connected");
		control_initialized = 0;
		query_list_network();
	} else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		warn("event (%x)", events);
		while ((e = bufferevent_get_openssl_error(bufev_sock)) > 0) {
			warn("%s", ERR_error_string(e, NULL));
		}
		bufferevent_free(bufev_sock);

		ev = event_new(base, -1, EV_TIMEOUT, on_timeout_cb, NULL);
		event_add(ev, &tv);
	}
}

DH *
get_dh_1024() {

	DH *dh = NULL;
	static unsigned char dh1024_p[]={
		0xDE,0xD3,0x80,0xD7,0xE1,0x8E,0x1B,0x5D,0x5C,0x76,0x61,0x79,
		0xCA,0x8E,0xCD,0xAD,0x83,0x49,0x9E,0x0B,0xC0,0x2E,0x67,0x33,
		0x5F,0x58,0x30,0x9C,0x13,0xE2,0x56,0x54,0x1F,0x65,0x16,0x27,
		0xD6,0xF0,0xFD,0x0C,0x62,0xC4,0x4F,0x5E,0xF8,0x76,0x93,0x02,
		0xA3,0x4F,0xDC,0x2F,0x90,0x5D,0x77,0x7E,0xC6,0x22,0xD5,0x60,
		0x48,0xF5,0xFB,0x5D,0x46,0x5D,0xF5,0x97,0x20,0x35,0xA6,0xEE,
		0xC0,0xA0,0x89,0xEE,0xAB,0x22,0x68,0x96,0x8B,0x64,0x69,0xC7,
		0xEB,0x41,0xDF,0x74,0xDF,0x80,0x76,0xCF,0x9B,0x50,0x2F,0x08,
		0x13,0x16,0x0D,0x2E,0x94,0x0F,0xEE,0x29,0xAC,0x92,0x7F,0xA6,
		0x62,0x49,0x41,0x0F,0x54,0x39,0xAD,0x91,0x9A,0x23,0x31,0x7B,
		0xB3,0xC9,0x34,0x13,0xF8,0x36,0x77,0xF3,
	};

	static unsigned char dh1024_g[]={
		0x02,
	};

	if ((dh = DH_new()) == NULL) {
		return NULL;
	}

	dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
	dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

	if (dh->p == NULL || dh->g == NULL) {
		DH_free(dh);
		return NULL;
	}

	return dh;
}

SSL_CTX *
envssl_init()
{
	DH		*dh;
	SSL_CTX		*ctx;

	SSL_load_error_strings();
	SSL_library_init();
	RAND_poll();

	if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
		warn("SSL_CTX_new failed");
		return NULL;
	}

	if ((dh = get_dh_1024()) == NULL) {
		warn("get_dh_1024 failed");
		goto error;
	}

	if ((SSL_CTX_set_tmp_dh(ctx, dh)) == 0) {
		warn("SSL_CTX_set_tmp_dh failed");
		goto error;
	}

	//SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
	if ((SSL_CTX_set_cipher_list(ctx, "AES256-GCM-SHA384")) == 0) {
		warn("SSL_CTX_set_cipher failed");
		goto error;
	}

	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	if ((SSL_CTX_use_certificate(ctx, passport->certificate)) == 0) {
		warn("SSL_CTX_use_certificate failed");
		goto error;
	}

	if ((SSL_CTX_use_PrivateKey(ctx, passport->keyring)) == 0) {
		warn("SSL_CTX_use_PrivateKey failed");
		goto error;
	}

	DH_free(dh);
	return ctx;

error:
	DH_free(dh);
	SSL_CTX_free(ctx);
	return NULL;
}

static int
new_peer()
{
	int			 flag = 1;
	int			 fd = -1;
	struct sockaddr_in	 sin;
	SSL_CTX			*ctx;
	SSL			*ssl;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(9093);

	if ((fd = socket(sin.sin_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		warn("socket failed");
		goto error;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		warn("setsockopt failed");
		goto error;
	}

	if (evutil_make_socket_nonblocking(fd) < 0) {
		warn("evutil_make_socket_nonblocking failed");
		goto error;
	}	

	if ((ctx = envssl_init()) == NULL) {
		warn("evssl_init failed");
		goto error;
	}

	if ((ssl = SSL_new(ctx)) == NULL) {
		warn("SSL_new failed");
		goto error;
	}

	if ((bufev_sock = bufferevent_openssl_socket_new(base, fd, ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		warn("bufferevent_socket_new failed");
		goto error;
	}

	bufferevent_enable(bufev_sock, EV_READ|EV_WRITE);
	bufferevent_setcb(bufev_sock, on_read_cb, NULL, on_event_cb, NULL);

	if (bufferevent_socket_connect(bufev_sock,
	    (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		warn("bufferevent_socket_connected failed");
		goto error;
	}

	return 0;

error:
	if (bufev_sock != NULL)
		bufferevent_free(bufev_sock);
	return -1;
}

int
control_init(json_t *config)
{
	static struct event	*ev_int;
	const char		*cert;
	const char		*pkey;
	const char		*cacert;

	if (json_unpack(config, "{s:s}", "certificate", &cert) < 0)
		err(1, "%s:%d", "certificate not found in config", __LINE__);

	if (json_unpack(config, "{s:s}", "privatekey", &pkey) < 0)
		err(1, "%s:%d", "privatekey not found in config", __LINE__);

	if (json_unpack(config, "{s:s}", "cacertificate", &cacert) < 0)
		err(1, "%s:%d", "trusted_cert not found in config", __LINE__);

	if ((passport = pki_passport_load_from_file(cert,
	    pkey, cacert)) == NULL)
		err(1, "%s:%d", "pki_passport_load_from_file", __LINE__);

	if ((base = event_base_new()) == NULL) {
		goto error;
	}

	if ((ev_int = evsignal_new(base, SIGHUP, sighandler, NULL)) == NULL) {
		goto error;
	}

	if (event_add(ev_int, NULL) < 0) {
		goto error;
	}

	if (new_peer() == -1) {
		goto error;
	}

	event_base_dispatch(base);

	if (bufev_sock != NULL) {
		bufferevent_free(bufev_sock);
	}

	event_base_free(base);
	return 0;

error:
	event_base_free(base);
	return -1;
}

void
control_fini()
{
	pki_passport_destroy(passport);
	vnetworks_free();
}
