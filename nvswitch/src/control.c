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

struct vlink {
	passport_t		*passport;
	struct event		*ev_reconnect;
	struct event		*ev_keepalive;
	struct event		*ev_readagain;
	struct tls_peer		*peer;
};

struct tls_peer {
	SSL			*ssl;
	SSL_CTX			*ctx;
	struct bufferevent	*bev;
	struct vlink		*vlink;
	int			 sock;
	int			 status;
};

static int		 request_node_list(struct bufferevent *bev);
static int		 request_network_list(struct bufferevent *bev);

static int		 response_node_delete(json_t *);
static int		 response_network_delete(json_t *);
static int		 response_node_list(json_t *);
static int		 response_network_list(json_t *);

static void		 tls_peer_free(struct tls_peer *);
static struct tls_peer	*tls_peer_new();

static int		 cert_verify_cb(int, X509_STORE_CTX *);
static void		 info_cb(const SSL *, int, int);
static SSL_CTX		*ctx_init();

static void		 vlink_free(struct vlink *);
static int		 vlink_connect(struct tls_peer *, struct vlink *);
static void		 vlink_keepalive(evutil_socket_t, short, void *);
static void		 vlink_readagain(evutil_socket_t, short, void *);
static void		 vlink_reconnect(evutil_socket_t, short, void *);
static void		 vlink_reset(struct vlink *vlink);

static void		 peer_read_cb(struct bufferevent *, void *);
static void		 peer_event_cb(struct bufferevent *, short, void *);

struct vlink	*vlink;

int
response_node_delete(json_t *jmsg)
{
	json_t		*jnodes;
	json_t		*jnode;
	struct vnetwork	*vnet;
	struct node	*node;
	size_t		 i;
	size_t		 array_size;
	char		*network_uid;
	const char	*uid;

	if ((jnodes = json_object_get(jmsg, "nodes")) == NULL) {
		log_warnx("%s: json_object_get failed", __func__);
		return (-1);
	}

	if ((array_size = json_array_size(jnodes)) == 0) {
		log_warnx("%s: json_array_size", __func__);
		return (-1);
	}

	for (i = 0; i < array_size; i++) {

		if ((jnode = json_array_get(jnodes, i)) == NULL) {
			log_warnx("%s: json_array_get", __func__);
			return (-1);
		}

		if (json_unpack(jnode, "{s:s, s:s}", "uid", &uid,
		    "network_uid", &network_uid) < 0) {
			log_warnx("%s: json_unpack failed", __func__);
			return (-1);
		}

		if ((vnet = vnetwork_find(network_uid)) == NULL) {
			log_warnx("%s: vnetwork_find", __func__);
			return (0);
		}

		if ((node = vnetwork_find_node(vnet, uid)) == NULL) {
			log_warnx("%s: vnetwork_find_node (%s)", __func__, uid);
			return (0);
		}

		vnetwork_del_node(vnet, node);
	}

	return (0);
}

int
response_network_delete(json_t *jmsg)
{
	json_t		*jnetworks;
	json_t		*jnetwork;
	struct vnetwork	*vnet = NULL;
	size_t		 i;
	size_t		 array_size;
	char		*network_uid;

	if ((jnetworks = json_object_get(jmsg, "networks")) == NULL) {
		log_warnx("%s: json_object_get failed", __func__);
		return (-1);
	}

	if ((array_size = json_array_size(jnetworks)) == 0) {
		log_warnx("%s: json_array_size", __func__);
		return (-1);
	}

	for (i = 0; i < array_size; i++) {

		if ((jnetwork = json_array_get(jnetworks, i)) == NULL) {
			log_warnx("%s: json_array_get", __func__);
			return (-1);
		}

		if (json_unpack(jnetwork, "{s:s}", "uid", &network_uid) < 0) {
			log_warnx("%s: json_unpack failed", __func__);
			return (-1);
		}

		if ((vnet = vnetwork_find(network_uid)) == NULL) {
			log_warnx("%s: vnetwork_find", __func__);
			return (0);
		}

		vnetwork_del(vnet);
	}

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

		if ((vnet = vnetwork_find(network_uid)) != NULL)
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

		vnetwork_add(uid, cert, pvkey, cacert);
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
request_update_node_status(char *status, char *ipsrc, char *uid, char *network_uid)
{
	json_t		*query = NULL;
	json_t		*node = NULL;
	struct evbuffer	*buf = NULL;
	int		 ret;
	char		*query_str = NULL;

	ret = -1;
	if ((query = json_object()) == NULL) {
		log_warnx("%s: query json_object", __func__);
		goto out;
	}

	if ((json_object_set_new(query, "action", json_string("switch-update-node-status"))) == -1) {
		log_warnx("%s: json_object_set_new action", __func__);
		goto out;
	}

	if ((node = json_object()) == NULL) {
		log_warnx("%s: node json_object", __func__);
		goto out;
	}

	if ((json_object_set_new(query, "node", node)) == -1) {
		log_warnx("%s: json_object_set_new node", __func__);
		goto out;
	}

	if ((json_object_set_new(node, "status", json_string(status))) == -1) {
		log_warnx("%s: json_object_set_new status", __func__);
		goto out;
	}

	if ((json_object_set_new(node, "ipsrc", json_string(ipsrc))) == -1) {
		log_warnx("%s: json_object_set_new ipsrc", __func__);
		goto out;
	}

	if ((json_object_set_new(node, "uid", json_string(uid))) == -1) {
		log_warnx("%s: json_object_set_new uid", __func__);
		goto out;
	}

	if ((json_object_set_new(node, "networkuid", json_string(network_uid))) == -1) {
		log_warnx("%s: json_object_set_new networkuid", __func__);
		goto out;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto out;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto out;
	}

	if (evbuffer_add_reference(buf, query_str,
	    strlen(query_str), NULL, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto out;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto out;
	}

	if (bufferevent_write_buffer(vlink->peer->bev, buf) < 0) {
		log_warnx("%s: bufferevent_write_buffer", __func__);
		goto out;
	}

	ret = 0;

out:
	if (buf != NULL)
		evbuffer_free(buf);
	json_decref(query);
	free(query_str);
	return (ret);
}

int
request_node_list(struct bufferevent *bev)
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

	if (bufferevent_write_buffer(bev, buf) < 0) {
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
request_network_list(struct bufferevent *bev)
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

	if (bufferevent_write_buffer(bev, buf) < 0) {
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
tls_peer_free(struct tls_peer *p)
{
	if (p == NULL)
		return;

	if (p->vlink != NULL)
		p->vlink->peer = NULL;

	if (p->bev != NULL)
		bufferevent_free(p->bev);
	else
		SSL_free(p->ssl);

	if (p->ctx != NULL) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined (LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
                // Remove the reference to the store, otherwise OpenSSL will try to free it.
                // OpenSSL 1.0.1 doesn't have the function X509_STORE_up_ref().
                p->ctx->cert_store = NULL;
#endif
                SSL_CTX_free(p->ctx);
        }

	free(p);

	return;
}

struct tls_peer *
tls_peer_new()
{
	struct tls_peer		*p;

	if ((p = malloc(sizeof(struct tls_peer))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	p->ssl = NULL;
	p->ctx = NULL;
	p->bev = NULL;
	p->vlink = NULL;
	p->status = 0;

	if ((p->ctx = ctx_init()) == NULL) {
		log_warnx("%s: ctx_init", __func__);
		goto error;
	}

	if ((p->ssl = SSL_new(p->ctx)) == NULL ||
	    SSL_set_app_data(p->ssl, p) != 1) {
		log_warnx("%s: SSL_new", __func__);
		goto error;
	}

	return (p);

error:
	tls_peer_free(p);
	return (NULL);
}

int
cert_verify_cb(int ok, X509_STORE_CTX *store)
{
        X509            *cert;
        X509_NAME       *name;
        char             buf[256];

        cert = X509_STORE_CTX_get_current_cert(store);
        name = X509_get_subject_name(cert);
        X509_NAME_get_text_by_NID(name, NID_commonName, buf, 256);

        printf("CN: %s\n", buf);

        return (ok);
}

void
info_cb(const SSL *ssl, int where, int ret)
{
        (void)ssl;
        (void)ret;

        if ((where & SSL_CB_HANDSHAKE_DONE) == 0)
                return;

        printf("connected to controller !\n");
}

SSL_CTX *
ctx_init()
{
	EC_KEY		*ecdh = NULL;
	SSL_CTX		*ctx = NULL;
	int		 err = -1;

	if ((ctx = SSL_CTX_new(TLS_method())) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		goto error;
	}

	if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-CHACHA20-POLY1305") != 1) {
		log_warnx("%s: SSL_CTX_set_cipher", __func__);
		goto error;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("%s: EC_KEY_new_by_curve_name", __func__);
		goto error;
	}

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) {
		log_warnx("%s: SSL_CTX_set_tmp_ecdh", __func__);
		goto error;
	}

	SSL_CTX_set_verify(ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_cb);

	SSL_CTX_set_info_callback(ctx, info_cb);

	err = 0;

error:
	if (err < 0) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
	EC_KEY_free(ecdh);
	return (ctx);
}

void
vlink_free(struct vlink *v)
{
	if (v == NULL)
		return;

	pki_passport_destroy(v->passport);
	event_free(v->ev_reconnect);
	event_free(v->ev_keepalive);
	event_free(v->ev_readagain);
	tls_peer_free(v->peer);
	free(v);
}

int
vlink_connect(struct tls_peer *p, struct vlink *v)
{
	EC_KEY			*ecdh = NULL;
	struct addrinfo		 hints;
	struct addrinfo		*res = NULL;
	struct timeval		 tv;
	int			 ret;
	int			 err = -1;
	int			 flag;
	const char		*local = "127.0.0.1";
	const char		*port = "9093";

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (event_add(v->ev_reconnect, &tv) < 0) {
		log_warn("%s: event_add", __func__);
		goto out;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((ret = getaddrinfo(local, port, &hints, &res)) < 0) {
		log_warnx("%s: getaddrinfo %s", __func__, gai_strerror(err));
		goto out;
	}

	if ((p->sock = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_warn("%s: socket", __func__);
		goto out;
	}

	flag = 1;
	if (setsockopt(p->sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(p->sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		log_warn("%s: setsockopt", __func__);
		goto out;
	}

	if (evutil_make_socket_nonblocking(p->sock) < 0) {
		log_warn("%s: evutil_make_socket_nonblocking", __func__);
		goto out;
	}

	SSL_CTX_set_cert_store(p->ctx, vlink->passport->cacert_store);
	X509_STORE_up_ref(vlink->passport->cacert_store);

	SSL_set_SSL_CTX(p->ssl, p->ctx);

	if ((SSL_use_certificate(p->ssl, vlink->passport->certificate)) != 1) {
		log_warnx("%s: SSL_CTX_use_certificate", __func__);
		goto out;
	}

	if ((SSL_use_PrivateKey(p->ssl, vlink->passport->keyring)) != 1) {
		log_warnx("%s: SSL_CTX_use_PrivateKey", __func__);
		goto out;
	}

	if ((p->bev = bufferevent_openssl_socket_new(ev_base, p->sock, p->ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE))
	    == NULL) {
		log_warnx("%s: bufferevent_openssl_socket_new", __func__);
		goto out;
	}

	bufferevent_setcb(p->bev, peer_read_cb, NULL, peer_event_cb, p);
	bufferevent_enable(p->bev, EV_READ | EV_WRITE);

	if (bufferevent_socket_connect(p->bev, res->ai_addr, res->ai_addrlen) < 0) {
		log_warnx("%s: bufferevent_socket_connected", __func__);
		goto out;
	}

	err = 0;

out:
	EC_KEY_free(ecdh);
	freeaddrinfo(res);

	return (err);
}

void
vlink_keepalive(evutil_socket_t fd, short event, void *arg)
{
	struct vlink	*v = arg;
	const char	*k = "{\"action\": \"keepalive\"}\n";
	(void)fd;
	(void)event;

	bufferevent_write(v->peer->bev, k, strlen(k));
}

void
vlink_readagain(evutil_socket_t fd, short event, void *arg)
{
}

void
vlink_reconnect(evutil_socket_t fd, short event, void *arg)
{
	struct vlink	*vlink = arg;
	(void)fd;
	(void)event;

	printf("vlink reconnect\n");

	if (vlink->peer != NULL)
		tls_peer_free(vlink->peer);

	if ((vlink->peer = tls_peer_new()) == NULL) {
		log_warnx("%s: tls_peer_new", __func__);
		goto error;
	}
	vlink->peer->vlink = vlink;

	if (vlink_connect(vlink->peer, vlink) < 0) {
		log_warnx("%s: vlink_connect", __func__);
		goto error;
	}

	return;

error:
	vlink_reset(vlink);
	return;
}

void
vlink_reset(struct vlink *vlink)
{
	struct timeval	 wait_sec = {5, 0};

	printf("reconnect control...\n");
	event_del(vlink->ev_keepalive);
	event_del(vlink->ev_readagain);
	event_del(vlink->ev_reconnect);

	if (vlink->peer) {
		vlink->peer->status = 0;

		if (vlink->peer->bev) {
			bufferevent_set_timeouts(vlink->peer->bev, NULL, NULL);
			bufferevent_disable(vlink->peer->bev, EV_READ | EV_WRITE);
		}
	}

	if (event_base_once(ev_base, -1, EV_TIMEOUT,
	    vlink_reconnect, vlink, &wait_sec) < 0)
		log_warnx("%s: event_base_once", __func__);
}

void
peer_read_cb(struct bufferevent *bev, void *arg)
{
	json_error_t		error;
	json_t			*jmsg = NULL;
	struct tls_peer		*p = arg;
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
				if (request_node_list(bev) < 0) {
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

	vlink_reset(p->vlink);
	return;
}

void
peer_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct tls_peer	*p = arg;
	struct timeval	 tv;
	unsigned long	 e;

	if (events & BEV_EVENT_CONNECTED) {

		printf("connected to controller!\n");

		event_del(p->vlink->ev_reconnect);

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		bufferevent_set_timeouts(p->bev, &tv, NULL);


		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if (event_add(p->vlink->ev_keepalive, &tv) < 0) {
			log_warn("%s: event_add", __func__);
		}

		control_init_done = 0;
		request_network_list(bev);

	} else if (events & (BEV_EVENT_TIMEOUT | BEV_EVENT_EOF | BEV_EVENT_ERROR)) {

		printf("disconnected from controller\n");

		while ((e = bufferevent_get_openssl_error(bev)) > 0)
			log_warnx("%s: ssl error: %s", __func__,
			    ERR_error_string(e, NULL));

		goto error;
	}

	return;

error:
	vlink_reset(p->vlink);
	return;
}

void
control_init()
{
	const char	*cert, *pvkey, *cacert;

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

	if ((vlink = malloc(sizeof(struct vlink))) == NULL)
		fatalx("%s: malloc", __func__);
	vlink->passport = NULL;
	vlink->peer = NULL;
	vlink->ev_reconnect = NULL;
	vlink->ev_keepalive = NULL;
	vlink->ev_readagain = NULL;

	// XXX show which files doesn't get loaded
	if ((vlink->passport =
	    pki_passport_load_from_file(cert, pvkey, cacert)) == NULL)
		fatalx("pki_passport_load_from_file");

	if ((vlink->ev_reconnect = event_new(ev_base, 0,
	    EV_TIMEOUT, vlink_reconnect, vlink)) == NULL)
		fatalx("%s: event_new", __func__);

	if ((vlink->ev_keepalive = event_new(ev_base, 0,
	    EV_TIMEOUT | EV_PERSIST, vlink_keepalive, vlink)) == NULL)
		fatalx("%s: event_new", __func__);

	if ((vlink->ev_readagain = event_new(ev_base, 0,
	    EV_TIMEOUT, vlink_readagain, vlink)) == NULL)
		fatalx("%s: event_new", __func__);

	event_active(vlink->ev_reconnect, EV_TIMEOUT, 0);
}

void
control_fini()
{
	vlink_free(vlink);
}
