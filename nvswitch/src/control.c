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

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <netinet/tcp.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <jansson.h>

#include <log.h>

#include "vnetwork.h"
#include "switch.h"

static int	 request_node_list();
static int	 request_network_list();

static int	 response_node_delete(json_t *);
static int	 response_network_delete(json_t *);
static int	 response_node_list(json_t *);
static int	 response_network_list(json_t *);

static void	 on_read_cb(struct bufferevent *, void *);
static void	 on_event_cb(struct bufferevent *, short, void *);

static int	 new_peer();
static DH	*get_dh_1024();
static SSL_CTX	*evssl_init();

static struct bufferevent	*bufev_sock;
static passport_t		*passport;

int
response_node_delete(json_t *jmsg)
{
	struct vnetwork	*vnet;
	struct session	*session;
	json_t		*node;
	char		*network_uuid;
	char		*uuid;

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
response_network_delete(json_t *jmsg)
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
response_node_list(json_t *jmsg)
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
		log_warnx("json_object_get failed");
		return -1;
	}

	if ((array_size = json_array_size(js_nodes)) == 0) {
		log_warnx("json_array_size failed");
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
response_network_list(json_t *jmsg)
{
	json_t	*jnetworks;
	json_t	*jnetwork;
	size_t	 index;

	int	 ret;
	char	*response;
	char	*uid;
	char	*cert;
	char	*pvkey;
	char	*cacert;

	static	size_t	 total = 1;

	ret = 0;
	if ((json_unpack(jmsg, "{s:s}", "response", &response)) < 0) {
		log_warnx("%s: json_unpack", __func__);
		ret = -1;
		goto out;
	}

	if ((jnetworks = json_object_get(jmsg, "networks")) == NULL) {
		log_warnx("%s: json_object_get", __func__);
		ret = -1;
		goto out;
	}

	json_array_foreach(jnetworks, index, jnetwork) {

		if (json_unpack(jnetwork, "{s:s,s:s,s:s,s:s}", "uid", &uid,
		    "cert", &cert, "pvkey", &pvkey, "cacert", &cacert) < 0)
			log_warnx("%s: json_unpack", __func__);

		//vnetwork_create(uid, cert, pvkey, cacert);
	}


	if (strncmp(response, "success", 7) == 0)
		log_debug("fetched %d network", total);
	else if (strncmp(response, "more-data", 9) == 0)
		total++;
	else
		ret = -1;

out:
	return (ret);
}

int
request_node_list()
{
	struct evbuffer	*buf = NULL;
	json_t		*request = NULL;
	int		 ret;
	char		*request_str = NULL;

	ret = -1;
	if ((request = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if (json_object_set_new(request, "action",
	    json_string("switch-node-list")) == -1) {
		log_warnx("%s: json_object_set_new", __func__);
		goto error;
	}

	if ((request_str = json_dumps(request, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto error;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto error;
	}

	if (evbuffer_add_reference(buf, request_str,
	    strlen(request_str), NULL, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto error;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto error;
	}

	if (bufferevent_write_buffer(bufev_sock, buf) < 0) {
		log_warnx("%s: bufferevent_write_buffer", __func__);
		goto error;
	}

	ret = 0;

error:
	if (buf != NULL)
		evbuffer_free(buf);
	json_decref(request);
	free(request_str);
	return (ret);
}

int
request_network_list()
{
	struct evbuffer	*buf = NULL;
	json_t		*request = NULL;
	int		 ret;
	char		*request_str = NULL;

	ret = -1;
	if ((request = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(request, "action",
	    json_string("switch-network-list")) == -1) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if ((request_str = json_dumps(request, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto error;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto error;
	}

	if (evbuffer_add_reference(buf, request_str, strlen(request_str), NULL,
	    NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto error;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto error;
	}

	if (bufferevent_write_buffer(bufev_sock, buf) < 0) {
		log_warnx("%s: bufferevent_write_buffer", __func__);
		goto error;
	}

	ret = 0;

error:
	if (buf != NULL)
		evbuffer_free(buf);
	json_decref(request);
	free(request_str);
	return (ret);
}

void
on_read_cb(struct bufferevent *bev, void *arg)
{
	json_error_t		error;
	json_t			*jmsg = NULL;
	size_t			n_read_out;
	const char		*action;
	char			*msg = NULL;

	while (evbuffer_get_length(bufferevent_get_input(bev)) > 0) {

		if ((msg = evbuffer_readln(bufferevent_get_input(bev),
		    &n_read_out, EVBUFFER_EOL_LF)) == NULL)
			return;

		if ((jmsg = json_loadb(msg, n_read_out, 0, &error)) == NULL) {
			log_warnx("%s: json_loadb: %s", __func__, error.text);
			goto error;
		}

		if (json_unpack(jmsg, "{s:s}", "action", &action) < 0) {
			log_warnx("%s: json_unpack", __func__);
			goto error;
		}

		if (strcmp(action, "switch-network-list") == 0) {
			if (response_network_list(jmsg) < 0) {
				log_warnx("%s: response_network_list", __func__);
				goto error;
			}
			if (control_init_done == 0) {
				log_info("networks initalized");
				if (request_node_list(jmsg) < 0) {
					log_warnx("%s: request_node_list",
					    __func__);
					goto error;
				}
			}
		} else if (strcmp(action, "switch-node-list") == 0) {
			if (response_node_list(jmsg) < 0) {
				log_warnx("%s: response_node_list", __func__);
				goto error;
			}
			if (control_init_done == 0) {
				control_init_done = 1;
				log_info("nodes initialized");
			}
		} else if (strcmp(action, "switch-network-delete") == 0) {
			if (response_network_delete(jmsg) < 0) {
				log_warnx("%s: response_network_delete",
				    __func__);
				goto error;
			}
		} else if (strcmp(action, "switch-node-delete") == 0) {
			if (response_node_delete(jmsg) < 0) {
				log_warnx("%s: response_node_delete", __func__);
				goto error;
			}
		}

		json_decref(jmsg);
		free(msg);
	}

	return;

error:
	json_decref(jmsg);
	free(msg);
	/* Disconnect */
	bufferevent_free(bev);
}

void
on_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	new_peer();
}

void
on_event_cb(struct bufferevent *bufev_sock, short events, void *arg)
{
	struct event	*ev;
	struct timeval	 tv = {1, 0};
	unsigned long	 e = 0;

	if (events & BEV_EVENT_CONNECTED) {

		control_init_done = 0;
		request_network_list();

	} else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {

		while ((e = bufferevent_get_openssl_error(bufev_sock)) > 0)
			log_warnx("%s: ssl error: %s", __func__,
			    ERR_error_string(e, NULL));

		bufferevent_free(bufev_sock);
		ev = event_new(ev_base, -1, EV_TIMEOUT, on_timeout_cb, NULL);
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
		return (NULL);
	}

	dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
	dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

	if (dh->p == NULL || dh->g == NULL) {
		DH_free(dh);
		return (NULL);
	}

	return (dh);
}

SSL_CTX *
evssl_init()
{
	DH		*dh = NULL;
	EC_KEY		*ecdh = NULL;
	SSL_CTX		*ctx = NULL;
	int		 ret;

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		return (NULL);

	ret = -1;
	if ((ctx = SSL_CTX_new(TLSv1_2_method())) == NULL) {
		log_warnx("SSL_CTX_new");
		return (NULL);
	}

	if ((dh = get_dh_1024()) == NULL) {
		log_warnx("get_dh_1024");
		goto error;
	}

	if ((SSL_CTX_set_tmp_dh(ctx, dh)) != 1) {
		log_warnx("SSL_CTX_set_tmp_dh");
		goto error;
	}

	if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-CHACHA20-POLY1305") != 1) {
		log_warnx("SSL_CTX_set_cipher");
		goto error;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("EC_KEY_new_by_curve_name");
		goto error;
	}

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) {
		log_warnx("SSL_CTX_set_tmp_ecdh");
		goto error;
	}

	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	if ((SSL_CTX_use_certificate(ctx, passport->certificate)) != 1) {
		log_warnx("SSL_CTX_use_certificate");
		goto error;
	}

	if ((SSL_CTX_use_PrivateKey(ctx, passport->keyring)) != 1) {
		log_warnx("SSL_CTX_use_PrivateKey");
		goto error;
	}

	ret = 0;

error:
	if (ret < 0) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
	DH_free(dh);
	EC_KEY_free(ecdh);
	return (ctx);
}

int
new_peer()
{
	SSL			*ssl;
	SSL_CTX			*ctx;
	struct addrinfo		*res;
	struct addrinfo		 hints;
	int			 ret;
	int			 flag = 1;
	int			 fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo("127.0.0.1", "9093", &hints, &res);

	ret = -1;
	if ((fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_warn("%s: socket", __func__);
		goto error;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		log_warn("%s: setsockopt", __func__);
		goto error;
	}

	if (evutil_make_socket_nonblocking(fd) < 0) {
		log_warn("%s: evutil_make_socket_nonblocking", __func__);
		goto error;
	}	

	if ((ctx = evssl_init()) == NULL) {
		log_warnx("%s: evssl_init", __func__);
		goto error;
	}

	if ((ssl = SSL_new(ctx)) == NULL) {
		log_warnx("%s: SSL_new", __func__);
		goto error;
	}

	if ((bufev_sock = bufferevent_openssl_socket_new(ev_base, fd, ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		log_warnx("%s: bufferevent_socket_new failed", __func__);
		goto error;
	}

	bufferevent_enable(bufev_sock, EV_READ|EV_WRITE);
	bufferevent_setcb(bufev_sock, on_read_cb, NULL, on_event_cb, NULL);

	if (bufferevent_socket_connect(bufev_sock, res->ai_addr,
	    res->ai_addrlen) < 0) {
		log_warnx("%s: bufferevent_socket_connected failed", __func__);
		goto error;
	}

	ret = 0;

error:
	if (ret < 0 && bufev_sock != NULL)
		bufferevent_free(bufev_sock);
	freeaddrinfo(res);
	return (ret);
}

void
control_init()
{
	const char	*cert;
	const char	*pvkey, *cacert;

	if (json_unpack(config, "{s:s}", "certificate", &cert) < 0)
		fatalx("certificate not found in config");

	if (json_unpack(config, "{s:s}", "privatekey", &pvkey) < 0)
		fatalx("privatekey not found in config");

	if (json_unpack(config, "{s:s}", "cacertificate", &cacert) < 0)
		fatalx("trusted_cert not found in config");

	if ((passport = pki_passport_load_from_file(cert,
	    pvkey, cacert)) == NULL)
		fatalx("pki_passport_load_from_file");

	if (new_peer() < 0)
		fatalx("new_peer");
}

void
control_fini()
{
	if (bufev_sock != NULL)
		bufferevent_free(bufev_sock);
	pki_passport_destroy(passport);
	vnetworks_free();
}
