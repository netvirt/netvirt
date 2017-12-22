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

#include "switch.h"

struct peer {
	struct bufferevent	*bufev;
	SSL			*ssl;
	SSL_CTX			*ctx;
	int			 fd;
};

static int		 request_node_list();
static int		 request_network_list();

static int		 response_node_delete(json_t *);
static int		 response_network_delete(json_t *);
static int		 response_node_list(json_t *);
static int		 response_network_list(json_t *);

static void		 on_read_cb(struct bufferevent *, void *);
static void		 on_event_cb(struct bufferevent *, short, void *);

static struct peer	*peer_new();
static void		 peer_free(struct peer *);

static SSL_CTX		*evssl_init();

static passport_t	*passport;
static struct peer	*peer;

int
response_node_delete(json_t *jmsg)
{
	json_t		*jnode;
	struct vnetwork	*vnet;
	struct node	*node;
	char		*network_uid;
	const char	*uid;

	if ((jnode = json_object_get(jmsg, "node")) == NULL) {
		log_warnx("%s: json_object_get failed", __func__);
		return (-1);
	}

	if (json_unpack(jnode, "{s:s, s:s}", "uid", &uid,
	    "network_uid", &network_uid) < 0) {
		log_warnx("%s: json_unpack failed", __func__);
		return (-1);
	}

	if ((vnet = vnetwork_lookup(network_uid)) == NULL) {
		log_warnx("%s: vnetwork_lookup", __func__);
		return (-1);
	}

	if ((node = vnetwork_find_node(vnet, uid)) == NULL) {
		log_warnx("%s: vnetwork_find_node", __func__);
		return (-1);
	}

	vnetwork_del_node(vnet, node);

	return (0);
}

int
response_network_delete(json_t *jmsg)
{
	json_t		*network;
	struct vnetwork	*vnet = NULL;
	char		*network_uid;

	if ((network = json_object_get(jmsg, "network")) == NULL) {
		log_warnx("%s: json_object_get failed", __func__);
		return (-1);
	}

	if (json_unpack(network, "{s:s}", "network_uid", &network_uid) < 0) {
		log_warnx("%s: json_unpack failed", __func__);
		return (-1);
	}

	if ((vnet = vnetwork_lookup(network_uid)) == NULL) {
		log_warnx("%s: vnetwork_lookup", __func__);
		return (-1);
	}

	vnetwork_free(vnet);

	return (0);
}

int
response_node_list(json_t *jmsg)
{
	char		*uid;
	char		*network_uid;
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

		if (json_unpack(node, "{s:s}", "uid", &uid) == -1 ||
		    json_unpack(node, "{s:s}", "network_uid", &network_uid) == -1) {
			warn("NULL parameter");
			return -1;
		}

		if ((vnet = vnetwork_lookup(network_uid)) != NULL)
			vnetwork_add_node(vnet, uid);
	}

	if ((json_unpack(jmsg, "{s:s}", "response", &response)) == -1) {
		warnx("json_unpack failed");
		return -1;
	}

	if (strcmp(response, "success") == 0) {
		warnx("fetched %zu node", total);
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

		vnetwork_create(uid, cert, pvkey, cacert);
	}


	if (strncmp(response, "success", 7) == 0) {
		log_debug("fetched %zu network", total);
		ret = 1;
	} else if (strncmp(response, "more-data", 9) == 0)
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
	    json_string("switch-node-list")) < 0) {
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

	if (bufferevent_write_buffer(peer->bufev, buf) < 0) {
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

	if (bufferevent_write_buffer(peer->bufev, buf) < 0) {
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
	int			 ret;
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
			if ((ret = response_network_list(jmsg)) < 0) {
				log_warnx("%s: response_network_list", __func__);
				goto error;
			}
			if (ret == 1 && control_init_done == 0) {
				log_warnx("networks initalized");
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
	peer_free(peer);
	peer = peer_new();
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

		while ((e = bufferevent_get_openssl_error(peer->bufev)) > 0)
			log_warnx("%s: ssl error: %s", __func__,
			    ERR_error_string(e, NULL));

		bufferevent_free(peer->bufev);

		ev = event_new(ev_base, -1, EV_TIMEOUT, on_timeout_cb, NULL);
		event_add(ev, &tv);
	}
}

SSL_CTX *
evssl_init()
{
	EC_KEY		*ecdh = NULL;
	SSL_CTX		*ctx = NULL;
	int		 ret;

	ret = -1;
	if ((ctx = SSL_CTX_new(TLSv1_2_method())) == NULL) {
		log_warnx("SSL_CTX_new");
		return (NULL);
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
	EC_KEY_free(ecdh);
	return (ctx);
}

void
peer_free(struct peer *p)
{
	free(p);
}

struct peer *
peer_new()
{
	struct peer		*p;
	struct addrinfo		*res = NULL;
	struct addrinfo		 hints;
	int			 flag = 1;

	if ((p = malloc(sizeof(struct peer))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	p->ssl = NULL;
	p->ctx = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo("127.0.0.1", "9093", &hints, &res);

	if ((p->fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_warn("%s: socket", __func__);
		goto error;
	}

	if (setsockopt(p->fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(p->fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		log_warn("%s: setsockopt", __func__);
		goto error;
	}

	if (evutil_make_socket_nonblocking(p->fd) < 0) {
		log_warn("%s: evutil_make_socket_nonblocking", __func__);
		goto error;
	}	

	if ((p->ctx = evssl_init()) == NULL) {
		log_warnx("%s: evssl_init", __func__);
		goto error;
	}

	if ((p->ssl = SSL_new(p->ctx)) == NULL) {
		log_warnx("%s: SSL_new", __func__);
		goto error;
	}

	if ((p->bufev = bufferevent_openssl_socket_new(ev_base, p->fd, p->ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		log_warnx("%s: bufferevent_socket_new failed", __func__);
		goto error;
	}

	bufferevent_enable(p->bufev, EV_READ|EV_WRITE);
	bufferevent_setcb(p->bufev, on_read_cb, NULL, on_event_cb, p);

	if (bufferevent_socket_connect(p->bufev, res->ai_addr,
	    res->ai_addrlen) < 0) {
		log_warnx("%s: bufferevent_socket_connected failed", __func__);
		goto error;
	}

	if (res != NULL)
		freeaddrinfo(res);

	return (p);

error:
	if (res != NULL)
		freeaddrinfo(res);

	peer_free(p);

	return (NULL);
}

void
control_init()
{
	const char	*cert;
	const char	*pvkey, *cacert;

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		fatalx("RAND_poll");

	if (json_unpack(config, "{s:s}", "cert", &cert) < 0)
		fatalx("'cert' not found in config");

	if (json_unpack(config, "{s:s}", "pvkey", &pvkey) < 0)
		fatalx("'pvkey' not found in config");

	if (json_unpack(config, "{s:s}", "cacert", &cacert) < 0)
		fatalx("'cacert' not found in config");

	// XXX show which files doesn't get loaded
	if ((passport = pki_passport_load_from_file(cert,
	    pvkey, cacert)) == NULL)
		fatalx("pki_passport_load_from_file");

	if ((peer = peer_new()) == NULL)
		fatalx("peer_new");
}

void
control_fini()
{
	pki_passport_destroy(passport);
	//vnetworks_free();
}
