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

#include <sys/socket.h>
#include <sys/tree.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <errno.h>

#include <log.h>
#include <pki.h>

#include "controller.h"
#include "dao.h"

RB_HEAD(tls_peer_tree, tls_peer);
RB_HEAD(node_tree, node);

struct vnetwork {
	RB_ENTRY(vnetwork)	 entry;
	struct tls_peer_tree	 peers;
	struct node_tree	 nodes;
	passport_t		*passport;
	SSL_CTX			*ctx;
	char			*uid;
	uint32_t		 active_node;
};

struct node {
	RB_ENTRY(node)		 entry;
	char			*network_uid;
	char			*description;
	char			*uid;
	char			*ipaddress;
	struct tls_peer		*peer;
};

struct tls_peer {
	RB_ENTRY(tls_peer)	 entry;
	struct sockaddr_storage	 ss;
	struct bufferevent	*bev;
	struct nodeinfo		*ni; // XXX cninfo
	struct vnetwork		*vnet;
	SSL			*ssl;
	SSL_CTX			*ctx;
	socklen_t		 ss_len;
};

RB_HEAD(vnetwork_tree, vnetwork);

static struct evconnlistener	*listener;
static struct vnetwork_tree	 vnetworks;

static int		 cert_verify_cb(int, X509_STORE_CTX *);
static int		 servername_cb(SSL *, int *, void *);

static int		 tls_peer_cmp(const struct tls_peer *,
		    const struct tls_peer *);
static struct tls_peer	*tls_peer_new(void);
static void		 tls_peer_free(struct tls_peer *);

static int		 vnetwork_cmp(const struct vnetwork *,
		    const struct vnetwork *);
static struct		 vnetwork *vnetwork_new(const char *, const char *,
		    const char *,const char *);
static void		 vnetwork_free(struct vnetwork *vnet);

static int	 	 node_cmp(const struct node *, const struct node *);
static struct node	*node_new(const char *, const char *, const char *,
		    const char *);
static void		 node_free(struct node *node);

static int		 network_listall_cb(void *, int, const char *,
		    const char *, const char *, const char *);
static int		node_listall_cb(void *, int, const char *, const char *,
		    const char *, const char *);

RB_PROTOTYPE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);
RB_PROTOTYPE_STATIC(tls_peer_tree, tls_peer, entry, tls_peer_cmp);
RB_PROTOTYPE_STATIC(node_tree, node, entry, node_cmp);

int
tls_peer_cmp(const struct tls_peer *a, const struct tls_peer *b)
{
        if (a->ss_len < b->ss_len)
                return (-1);
        if (b->ss_len > b->ss_len)
                return (1);
        return (memcmp(&a->ss, &b->ss, a->ss_len));
}

int
node_cmp(const struct node *a, const struct node *b)
{
	return strcmp(a->uid, b->uid);
}

int
vnetwork_cmp(const struct vnetwork *a, const struct vnetwork *b)
{
	return strcmp(a->uid, b->uid);
}

struct vnetwork *
vnetwork_new(const char *uid, const char *cert, const char *pvkey,
    const char *cacert)
{
	struct vnetwork	*vnet;

	if ((vnet = malloc(sizeof(*vnet))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	RB_INIT(&vnet->peers);
	RB_INIT(&vnet->nodes);
	vnet->uid = NULL;
	vnet->passport = NULL;
	vnet->ctx = NULL;

	if ((vnet->uid = strdup(uid)) == NULL) {
		log_warn("%s: strdup", __func__);
		goto error;
	}

	if ((vnet->passport =
	    pki_passport_load_from_memory(cert, pvkey, cacert)) == NULL) {
		log_warnx("%s: pki_passport_load_from_memory", __func__);
		goto error;
	}

	vnet->active_node = 0;

	return (vnet);

error:
	vnetwork_free(vnet);

	return (NULL);
}

void
vnetwork_free(struct vnetwork *vnet)
{
	if (vnet == NULL)
		return;

	pki_passport_destroy(vnet->passport);
	SSL_CTX_free(vnet->ctx);
	free(vnet->uid);
	free(vnet);
}

struct node *
node_new(const char *network_uid, const char *description, const char *uid,
    const char *ipaddress)
{
	struct node	*node;

	if ((node = malloc(sizeof(*node))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	node->network_uid = NULL;
	node->description = NULL;
	node->uid = NULL;
	node->ipaddress = NULL;

	if ((node->network_uid = strdup(network_uid)) == NULL ||
	    (node->description = strdup(description)) == NULL ||
	    (node->uid = strdup(uid)) == NULL ||
	    (node->ipaddress = strdup(ipaddress)) == NULL) {
		log_warn("%s: strdup", __func__);
		goto error;
	}

	return (node);

error:
	node_free(node);

	return (NULL);
}

void
node_free(struct node *node)
{
	if (node == NULL)
		return;

	free(node->network_uid);
	free(node->description);
	free(node->uid);
	free(node->ipaddress);
	free(node);
}

struct tls_peer *
tls_peer_new(void)
{
	struct tls_peer	*p;
	EC_KEY		*ecdh = NULL;

	if ((p = malloc(sizeof(*p))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	p->bev = NULL;
	p->ssl = NULL;
	p->ctx = NULL;

	if ((p->ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		goto error;
	}

	if (SSL_CTX_set_cipher_list(p->ctx, "ECDHE-ECDSA-CHACHA20-POLY1305")
	    != 1) {
		log_warnx("%s: SSL_CTX_set_cipher", __func__);
		goto error;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("%s: EC_KEY_new_by_curve_name", __func__);
		goto error;
	}

	if (SSL_CTX_set_tmp_ecdh(p->ctx, ecdh) != 1) {
		log_warnx("%s: SSL_CTX_set_tmp_ecdh", __func__);
		goto error;
	}

	SSL_CTX_set_tlsext_servername_callback(p->ctx, servername_cb);
	SSL_CTX_set_tlsext_servername_arg(p->ctx, p);

	if ((p->ssl = SSL_new(p->ctx)) == NULL ||
	    SSL_set_app_data(p->ssl, p) != 1) {
		log_warnx("%s: SSL_new", __func__);
		goto error;
	}

	SSL_set_verify_depth(p->ssl, 1);

	SSL_set_verify(p->ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_cb);

	EC_KEY_free(ecdh);

	return (p);

error:
	EC_KEY_free(ecdh);
	tls_peer_free(p);

	return (NULL);
}

void
tls_peer_free(struct tls_peer *p)
{
	if (p == NULL)
		return;

	if (p->bev != NULL)
		bufferevent_free(p->bev);
	SSL_free(p->ssl);
	SSL_CTX_free(p->ctx);
	free(p);
}

int
node_listall_cb(void *arg, int left, const char *network_uid,
    const char *description, const char *uid, const char *ipaddress)
{
	struct node	*node = NULL;
	struct vnetwork	 needle, *vnet;

	printf("node: %s\n", description);

	if ((node = node_new(network_uid, description, uid, ipaddress))
	    == NULL) {
		log_warnx("%s: node_new", __func__);
		goto error;
	}

	needle.uid = (char *)network_uid;
	if ((vnet = RB_FIND(vnetwork_tree, &vnetworks, &needle)) == NULL) {
		log_warnx("%s: node uid '%s' "
		    "doesn't belong to a network", __func__, uid);
		goto error;
	}

	RB_INSERT(node_tree, &vnet->nodes, node);

	return (0);

error:
	node_free(node);

	return (-1);
}

int
network_listall_cb(void *arg, int left, const char *uid, const char *cert,
    const char *pvkey, const char *cacert)
{
	struct vnetwork *vnet;

	printf("network: %s\n", uid);

	if ((vnet = vnetwork_new(uid, cert, pvkey, cacert)) == NULL) {
		log_warnx("%s: network_create", __func__);
		goto error;
	}

	RB_INSERT(vnetwork_tree, &vnetworks, vnet);

	return (0);

error:
	vnetwork_free(vnet);
	return (-1);
}

int
cert_verify_cb(int ok, X509_STORE_CTX *store)
{
	struct node	*node, needle;
	struct tls_peer	*p;
	X509		*cert;

	p = SSL_get_app_data(X509_STORE_CTX_get_ex_data(store,
	    SSL_get_ex_data_X509_STORE_CTX_idx()));

	if (X509_STORE_CTX_get_error_depth(store) == 0) {

		if ((cert = X509_STORE_CTX_get_current_cert(store)) == NULL) {
			log_warnx("%s: X509_STORE_CTX_GET_current_cert",
			    __func__);
			ok = 0;
			goto out;
		}

		if ((p->ni = cert_get_nodeinfo(cert)) == NULL) {
			log_warnx("%s: cert_get_nodeinfo", __func__);
			ok = 0;
			goto out;
		}

		printf("ni version: %s\n", p->ni->version);
		printf("ni type: %s\n", p->ni->type);
		printf("ni networkid: %s\n", p->ni->networkid);
		printf("ni nodeid: %s\n", p->ni->nodeid);

		needle.uid = (char *)p->ni->nodeid;
		if ((node = RB_FIND(node_tree, &p->vnet->nodes, &needle))
		    == NULL) {
			log_warnx("%s: node '%s' is not whitelisted",
			    __func__, p->ni->nodeid);
			ok = 0;
			goto out;
		}
	}

out:

	return (ok);
}

int
servername_cb(SSL *ssl, int *ad, void *arg)
{
	struct tls_peer	*p = arg;
	struct vnetwork	 needle;
	const char	*servername;

	if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
	    == NULL) {
		log_warnx("%s: SSL_get_servername", __func__);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}

	printf("server name %s\n", servername);

	needle.uid = (char *)servername;
	if ((p->vnet = RB_FIND(vnetwork_tree, &vnetworks, &needle)) == NULL) {
		log_warnx("%s: servername not found: %s", __func__, servername);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}

        SSL_CTX_set_cert_store(p->ctx, p->vnet->passport->cacert_store);

	SSL_set_SSL_CTX(p->ssl, p->ctx);
        if ((SSL_use_certificate(p->ssl, p->vnet->passport->certificate)) != 1) {
                log_warnx("%s: SSL_CTX_use_certificate", __func__);
        }

        if ((SSL_use_PrivateKey(p->ssl, p->vnet->passport->keyring)) != 1) {
                log_warnx("%s: SSL_CTX_use_PrivateKey", __func__);
        }

	return (SSL_TLSEXT_ERR_OK);
}

void
tls_peer_onread_cb(struct bufferevent *bev, void *arg)
{
	printf("tls_peer_onread_cb");
}

void
tls_peer_onevent_cb(struct bufferevent *bev, short events, void *arg)
{
	unsigned long	e;

	SSL_load_error_strings();

	if (events & BEV_EVENT_CONNECTED) {

		printf("event connected\n");

	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT | BEV_EVENT_EOF)) {

                while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			log_warnx("%s: TLS error: %s", __func__,
			    ERR_reason_error_string(e));
                }
	}
}

void
listen_accept_cb(struct evconnlistener *listener, int fd,
    struct sockaddr *address, int socklen, void *arg)
{
	struct tls_peer		*p;

	printf("listen_accept_cb\n");

	if ((p = tls_peer_new()) == NULL) {
		log_warnx("%s: tls_peer_new", __func__);
		goto error;
	}

	if ((p->bev = bufferevent_openssl_socket_new(
	    evconnlistener_get_base(listener), fd, p->ssl,
	    BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		log_warnx("%s: bufferevent_openssl_socket_new", __func__);
		goto error;
	}

	bufferevent_enable(p->bev, EV_READ | EV_WRITE);
	bufferevent_setcb(p->bev, tls_peer_onread_cb, NULL,
	    tls_peer_onevent_cb, p);

	return;

error:
	tls_peer_free(p);
	return;
}

void
listen_error_cb(struct evconnlistener *listener, void *arg)
{
	printf("listen_error_cb\n");
}

int
agent_control_init(void)
{
	struct addrinfo		*res;
	struct addrinfo		 hints;

	if (dao_switch_network_list(NULL, network_listall_cb) < 0) {
		log_warnx("%s: dao_switch_network_list", __func__);
		goto error;
	}

	if (dao_node_listall(NULL, node_listall_cb) < 0) {
		log_warnx("%s: dao_node_listall", __func__);
		goto error;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo("0.0.0.0", "7032", &hints, &res);

	if ((listener = evconnlistener_new_bind(ev_base, listen_accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
	    res->ai_addr, res->ai_addrlen)) == NULL) {
		log_warnx("%s: evconnlistener_new_bind", __func__);
		goto error;
	}
	evconnlistener_set_error_cb(listener, listen_error_cb);

	return (0);

error:

	return (-1);
}

void
agent_control_fini(void)
{
	// XXX free everything
}

RB_GENERATE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);
RB_GENERATE_STATIC(tls_peer_tree, tls_peer, entry, tls_peer_cmp);
RB_GENERATE_STATIC(node_tree, node, entry, node_cmp);
