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
#include <sys/types.h>
#include <sys/tree.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <err.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <log.h>
#include <pki.h>

#include "inet.h"
#include "switch.h"

RB_HEAD(acl_node_tree, node);
RB_HEAD(tls_peer_tree, tls_peer);
RB_HEAD(lladdr_tree, lladdr);

struct vnetwork {
	RB_ENTRY(vnetwork)	 entry;
	passport_t		*passport;
	struct acl_node_tree	 acl_node;
	struct lladdr_tree	 mac_table;
	struct tls_peer_tree	 peers;
	uint32_t		 active_node;
	char			*uid;
};

struct node {
	RB_ENTRY(node)		 entry;
	struct tls_peer		*peer;
	char			*uid;
};

struct lladdr {
	RB_ENTRY(lladdr)	 entry;
	uint8_t			 macaddr[ETHER_ADDR_LEN];
	struct tls_peer		*peer;
};

struct tls_peer {
	RB_ENTRY(tls_peer)	 entry;
	SSL			*ssl;
	SSL_CTX			*ctx;
	socklen_t		 ss_len;
	struct bufferevent	*bev;
	struct event		*timeout;
	struct node		*node;
	struct sockaddr_storage  ss;
	struct vnetwork		*vnet;
};

RB_HEAD(vnetwork_tree, vnetwork);

static struct evconnlistener	*listener = NULL;
static struct vnetwork_tree	 vnetworks;

static int		 lladdr_cmp(const struct lladdr *,
			    const struct lladdr *);
static void		 lladdr_free(struct lladdr *);
static struct lladdr	*lladdr_new(struct tls_peer *, uint8_t *);

static int		 node_cmp(const struct node *, const struct node *);
static void		 node_free(struct node *n);
static struct node	*node_new(const char *);

static int		 tls_peer_cmp(const struct tls_peer *,
			    const struct tls_peer *);
static void		 tls_peer_free(struct tls_peer *);
static struct tls_peer	*tls_peer_new();
static void		 tls_peer_disconnect(struct tls_peer *);
static void		 tls_peer_timeout_cb(int, short, void *);

static int		 vnetwork_cmp(const struct vnetwork *,
			    const struct vnetwork *);
static void		 vnetwork_free(struct vnetwork *);
static struct vnetwork	*vnetwork_new(char *, char *, char *, char *);

static SSL_CTX		*ctx_init(void *);

static int		 cert_verify_cb(int, X509_STORE_CTX *);
static void		 info_cb(const SSL *, int, int);
static int		 servername_cb(SSL *, int *, void *);

static void		 peer_event_cb(struct bufferevent *, short, void *);
static void		 peer_read_cb(struct bufferevent *, void *);
static void		 listen_error_cb(struct evconnlistener *, void *);
static void		 listen_conn_cb(struct evconnlistener *, int,
			    struct sockaddr *, int, void *);

RB_PROTOTYPE_STATIC(lladdr_tree, lladdr, entry, lladdr_cmp);
RB_PROTOTYPE_STATIC(acl_node_tree, node, entry, node_cmp);
RB_PROTOTYPE_STATIC(tls_peer_tree, tls_peer, entry, tls_peer_cmp);
RB_PROTOTYPE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);

int
lladdr_cmp(const struct lladdr *a, const struct lladdr *b)
{
	return memcmp(a->macaddr, b->macaddr, ETHER_ADDR_LEN);
}

void
lladdr_free(struct lladdr *l)
{
	if (l == NULL)
		return;

	free(l);
}

struct lladdr *
lladdr_new(struct tls_peer *p, uint8_t *macaddr)
{
	struct lladdr	*l;

	if ((l = malloc(sizeof(*l))) == NULL) {
		log_warnx("%s: malloc", __func__);
		goto error;
	}
	l->peer = p;

	memcpy(l->macaddr, macaddr, ETHER_ADDR_LEN);

	return (l);

error:
	lladdr_free(l);
	return (NULL);
}

int
node_cmp(const struct node *a, const struct node *b)
{
	return strcmp(a->uid, b->uid);
}

void
node_free(struct node *n)
{
	if (n == NULL)
		return;

	free(n->uid);
	free(n);
}

struct node *
node_new(const char *uid)
{
	struct node	*n = NULL;

	if ((n = malloc(sizeof(*n))) == NULL) {
		log_warnx("%s: malloc", __func__);
		goto error;
	}
	n->uid = strdup(uid);

	return (n);

error:
	node_free(n);
	return (NULL);
}

int
tls_peer_cmp(const struct tls_peer *a, const struct tls_peer *b)
{
	if (a->ss_len < b->ss_len)
		return (-1);
	if (a->ss_len > b->ss_len)
		return (1);
	return (memcmp(&a->ss, &b->ss, a->ss_len));
}

void
tls_peer_free(struct tls_peer *p)
{
	if (p == NULL)
		return;
	if (p->bev != NULL)
		bufferevent_free(p->bev);
	else
		SSL_free(p->ssl);

	event_free(p->timeout);
	SSL_CTX_free(p->ctx);
	free(p);
}

struct tls_peer *
tls_peer_new()
{
	struct tls_peer	*p;
	struct timeval	 tv = {10, 0};

	if ((p = malloc(sizeof(*p))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	p->ssl = NULL;
	p->ctx = NULL;
	p->ss_len = 0;
	p->bev = NULL;
	p->timeout = NULL;
	p->node = NULL;
	p->vnet = NULL;

	if ((p->timeout = evtimer_new(ev_base,
	    tls_peer_timeout_cb, p)) == NULL) {
		log_warnx("%s: evtimer_new", __func__);
		goto error;
	}

	if ((p->ctx = ctx_init(p)) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		goto error;
	}

	if ((p->ssl = SSL_new(p->ctx)) == NULL ||
	    SSL_set_app_data(p->ssl, p) != 1) {
		log_warnx("%s: SSL_new", __func__);
		goto error;
	}

	if (evtimer_add(p->timeout, &tv) < 0)
		goto error;

	return (p);

error:
	tls_peer_free(p);
	return (NULL);
}

void
tls_peer_disconnect(struct tls_peer *p)
{
	struct tls_peer *pp;
	struct lladdr	*l, *ll;

	if (p == NULL)
		return;

	if (p->vnet != NULL) {
		if ((pp = RB_FIND(tls_peer_tree, &p->vnet->peers, p)) != NULL)
			RB_REMOVE(tls_peer_tree, &p->vnet->peers, pp);
	}

	RB_FOREACH_SAFE(l, lladdr_tree, &p->vnet->mac_table, ll) {
		if (l->peer == p) {
			RB_REMOVE(lladdr_tree, &p->vnet->mac_table, l);
			lladdr_free(l);
		}
	}

	if (p->node != NULL && p->vnet != NULL)
		request_update_node_status("0", "", p->node->uid, p->vnet->uid);

	tls_peer_free(p);
}

void
tls_peer_timeout_cb(int fd, short event, void *arg)
{

}

int
vnetwork_cmp(const struct vnetwork *a, const struct vnetwork *b)
{
	return strcmp(a->uid, b->uid);
}

void
vnetwork_free(struct vnetwork *v)
{
	if (v == NULL)
		return;

	pki_passport_destroy(v->passport);
	free(v->uid);
	free(v);
}

struct vnetwork *
vnetwork_new(char *uid, char *cert, char *pvkey, char *cacert)
{
	struct vnetwork *v;

	if ((v = malloc(sizeof(*v))) == NULL) {
		log_warnx("%s: malloc", __func__);
		goto error;
	}
	v->passport = pki_passport_load_from_memory(cert, pvkey, cacert);
	RB_INIT(&v->acl_node);
	RB_INIT(&v->mac_table);
	RB_INIT(&v->peers);
	v->uid = strdup(uid);
	v->active_node = 0;

	return (v);

error:
	vnetwork_free(v);
	return (NULL);
}

int
vnetwork_add(char *uid, char *cert, char *pvkey, char *cacert)
{
	struct vnetwork	*v;

	if ((v = vnetwork_new(uid, cert, pvkey, cacert)) == NULL) {
		log_warnx("%s: vnetwork_new", __func__);
		goto error;
	}

	RB_INSERT(vnetwork_tree, &vnetworks, v);

	return (0);

error:
	return (-1);
}

void
vnetwork_del(struct vnetwork *v)
{
	struct lladdr		*lladdr;
	struct node		*node;
	struct tls_peer		*peer;

	RB_REMOVE(vnetwork_tree, &vnetworks, v);

	while ((lladdr = RB_ROOT(&v->mac_table)) != NULL) {
		RB_REMOVE(lladdr_tree, &v->mac_table, lladdr);
		lladdr_free(lladdr);
	}

	while ((peer = RB_ROOT(&v->peers)) != NULL)
		tls_peer_disconnect(peer);


	while ((node = RB_ROOT(&v->acl_node)) != NULL)
		vnetwork_del_node(v, node);
	vnetwork_free(v);
}

struct vnetwork
*vnetwork_find(const char *uid)
{
	struct vnetwork	needle;

	needle.uid = (char *)uid;
	return RB_FIND(vnetwork_tree, &vnetworks, &needle);
}

int
vnetwork_add_node(struct vnetwork *v, const char *uid)
{
	struct node	*n;

	if ((n = node_new(uid)) == NULL) {
		log_warnx("%s: node_new", __func__);
		goto error;
	}

	RB_INSERT(acl_node_tree, &v->acl_node, n);

	return (0);

error:
	return (-1);
}

void
vnetwork_del_node(struct vnetwork *vnet, struct node *node)
{
	// XXX safe to call if find() used first
	RB_REMOVE(acl_node_tree, &vnet->acl_node, node);

	node_free(node);

	// XXX if peer connected, free and disconnect
}

struct node *
vnetwork_find_node(struct vnetwork *v, const char *uid)
{
	struct node	 needle;

	needle.uid = (char *)uid;
	return RB_FIND(acl_node_tree, &v->acl_node, &needle);
}

void
switching(struct tls_peer *p, uint8_t *frame, size_t len)
{
	struct tls_peer		*pp;
	struct lladdr		*l, *ll, needle;
	int			 ret;
	uint8_t			 saddr[ETHER_ADDR_LEN];

	if (inet_ethertype(frame) == ETHERTYPE_PING) {
		if ((ret = bufferevent_write(p->bev, frame, len)) < 0) {
			log_warnx("%s: bufferevent_write: %d", __func__, ret);
			goto cleanup;
		}
		return;
	}

	inet_macaddr_src(frame, saddr);

	/* Make sure we know the source */
	inet_macaddr_src(frame, needle.macaddr);

	if ((l = RB_FIND(lladdr_tree, &p->vnet->mac_table, &needle))
	    == NULL) {
		if ((l = lladdr_new(p, (uint8_t *)&needle.macaddr))
		    == NULL)
			goto cleanup;
		RB_INSERT(lladdr_tree, &p->vnet->mac_table, l);
	}

	/* Verify if we know the destination */
	inet_macaddr_dst(frame, needle.macaddr);
	if ((ll = RB_FIND(lladdr_tree, &p->vnet->mac_table, &needle))
	    != NULL) {
		if (SSL_write(ll->peer->ssl, frame, len) <= 0) {
			log_warnx("%s: SSL_write", __func__);
			goto cleanup;
		}
	} else {
		/* Flooding */
		RB_FOREACH(pp, tls_peer_tree, &p->vnet->peers) {
			if (pp != p) {
				if (SSL_write(pp->ssl, frame, len) <= 0) {
					log_warnx("%s: SSL_write", __func__);
					goto cleanup;
				}
			}
		}
	}

	return;

cleanup:
	tls_peer_disconnect(p);
	return;
}

SSL_CTX *
ctx_init(void *arg)
{
	EC_KEY  *ecdh = NULL;
	SSL_CTX *ctx = NULL;
	int      err;

	SSL_load_error_strings();
	SSL_library_init();

	err = -1;

	if (!RAND_poll())
		goto out;

	if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
		log_warn("%s: SSL_CTX_new", __func__);
		goto out;
	}

	// XXX disable old versions : int SSL_CTX_set_max_proto_version
	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

	if (SSL_CTX_set_cipher_list(ctx,
	    "ECDHE-ECDSA-CHACHA20-POLY1305,"
	    "ECDHE-ECDSA-AES256-GCM-SHA384") != 1) {
		log_warn("%s: SSL_CTX_set_cipher", __func__);
		goto out;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warn("%s: EC_KEY_new_by_curve_name", __func__);
		goto out;
	}

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) {
		log_warn("%s: SSL_CTX_set_tmp_ecdh", __func__);
		goto out;
	}

	SSL_CTX_set_verify(ctx,
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_cb);

	SSL_CTX_set_tlsext_servername_callback(ctx, servername_cb);
	SSL_CTX_set_tlsext_servername_arg(ctx, arg);

	SSL_CTX_set_info_callback(ctx, info_cb);

	err = 0;

out:
	if (err < 0) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}

	EC_KEY_free(ecdh);
	return (ctx);
}

int
cert_verify_cb(int preverify_ok, X509_STORE_CTX *store)
{
	struct vnetwork 	*vnet;
	struct node		*node;
	struct certinfo		*ci = NULL;
	struct tls_peer		*p;
	X509			*cert;
	int			 ok;
	char			 cname[256];

	ok = 0; /* Failure */

	if (preverify_ok == 0) {
		log_warnx("%s: certificate preverify", __func__);
		goto out;
	}

	p = SSL_get_app_data(X509_STORE_CTX_get_ex_data(store,
	    SSL_get_ex_data_X509_STORE_CTX_idx()));

	cert = X509_STORE_CTX_get_current_cert(store);
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
	    NID_commonName, cname, sizeof(cname));

	if (strcmp(cname, "embassy") == 0) {
		ok = 1;
		goto out;
	}

	if ((ci = certinfo(cert)) == NULL) {
		log_warnx("%s: certinfo", __func__);
		goto out;
	}

	if ((vnet = vnetwork_find(ci->network_uid)) == NULL) {
		log_warnx("%s: vnetwork_find", __func__);
		goto out;
	}

	if ((node = vnetwork_find_node(vnet, ci->node_uid)) == NULL) {
		log_warnx("%s: vnetwork_find_node: access denied", __func__);
		goto out;
	}

	/* Associate the peer to a specific node */
	p->node = node;

	ok = 1; /* Success */

	printf("certificate ok\n");

out:
	certinfo_destroy(ci);
	return (ok);
}

void
info_cb(const SSL *ssl, int where, int ret)
{
	struct tls_peer		*p;
	char			 ipsrc[INET6_ADDRSTRLEN];

	if ((where & SSL_CB_HANDSHAKE_DONE) == 0)
		return;

	p = SSL_get_app_data(ssl);
	printf("inserted? %p\n", RB_INSERT(tls_peer_tree, &p->vnet->peers, p));

	// XXX make a function to return char *

	inet_ntop(p->ss.ss_family, &((struct sockaddr_in*)&p->ss)->sin_addr, ipsrc, sizeof(ipsrc)),
	    ntohs(&((struct sockaddr_in*)&p->ss)->sin_port);

	request_update_node_status("1", ipsrc, p->node->uid, p->vnet->uid);

	printf("info_cb ok <%s>\n", ipsrc);

	// XXX send gratuitous ARP / Neighbor Advertisement
}

int
servername_cb(SSL *ssl, int *ad, void *arg)
{
	struct tls_peer		*p = arg;
	const char		*servername;


	if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
	    == NULL) {
		log_warnx("%s: SSL_get_servername", __func__);
		goto error;
	}

	printf("servername %s\n", servername);

	if ((p->vnet = vnetwork_find(servername)) == NULL) {
		log_warnx("%s: servername not found: %s", __func__, servername);
		goto error;
	}

	/* Load the trusted certificate store into ctx */
	SSL_CTX_set_cert_store(p->ctx, p->vnet->passport->cacert_store);
	X509_STORE_up_ref(p->vnet->passport->cacert_store);

	SSL_set_SSL_CTX(p->ssl, p->ctx);
	if ((SSL_use_certificate(p->ssl, p->vnet->passport->certificate)) != 1) {
		log_warnx("%s: SSL_use_certificate", __func__);
		goto error;
	}

	if ((SSL_use_PrivateKey(p->ssl, p->vnet->passport->keyring)) != 1) {
		log_warnx("%s: SSL_CTX_use_PrivateKey", __func__);
		goto error;
	}

	return (SSL_TLSEXT_ERR_OK);

error:
	return (SSL_TLSEXT_ERR_ALERT_FATAL);
}

void
peer_event_cb(struct bufferevent *bev, short events, void *arg)
{
	unsigned long	 e;

	if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT | BEV_EVENT_EOF)) {
		printf("disconnected\n");
		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			log_warnx("%s: TLS error: %s", __func__,
			    ERR_reason_error_string(e));
		}
		tls_peer_disconnect(arg);
	}

	return;
}

void
peer_read_cb(struct bufferevent *bev, void *arg)
{
	struct evbuffer	*input;
	struct tls_peer	*p = arg;
	int		 n;
	uint8_t		 buf[2000];

	input = bufferevent_get_input(bev);

	n = evbuffer_remove(input, buf, sizeof(buf));
	printf("evbuffer remove: %d\n", n);

	switching(p, buf, n);

	return;

	goto error;

error:
	tls_peer_disconnect(p);
	return;
}

void
listen_error_cb(struct evconnlistener *l, void *arg)
{

}

void
listen_conn_cb(struct evconnlistener *l, int fd,
    struct sockaddr *address, int socklen, void *arg)
{
	struct tls_peer	*p;
	struct timeval	 tv;

	if ((p = tls_peer_new()) == NULL) {
		log_warnx("%s: tls_peer_new", __func__);
		goto error;
	}
	memcpy(&p->ss, address, socklen);
	p->ss_len = socklen;

	if ((p->bev = bufferevent_openssl_socket_new(
	    evconnlistener_get_base(listener), fd, p->ssl,
	    BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		log_warnx("%s: bufferevent_openssl_socket_new", __func__);
		goto error;
	}

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	bufferevent_set_timeouts(p->bev, &tv, NULL);

	bufferevent_enable(p->bev, EV_READ | EV_WRITE);
	bufferevent_setcb(p->bev, peer_read_cb, NULL,
	    peer_event_cb, p);

	return;

error:
	tls_peer_free(p);
	return;
}

void
switch_init(json_t *config)
{
	struct addrinfo	 hints, *ai;
	int		 status;
	const char	*ip;
	const char	*port;

	if (json_unpack(config, "{s:s}", "switch_ip", &ip) < 0)
		fatalx("%s: switch_ip not found in config", __func__);

	if (json_unpack(config, "{s:s}", "switch_port", &port) < 0)
		fatalx("%s: switch_port not found config", __func__);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		fatalx("%s: getaddrinfo: %s", __func__, gai_strerror(status));

	if ((listener = evconnlistener_new_bind(ev_base, listen_conn_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
	    ai->ai_addr, ai->ai_addrlen)) == NULL)
		fatalx("%s: evconnlistener_new_bind", __func__);

	evconnlistener_set_error_cb(listener, listen_error_cb);

	freeaddrinfo(ai);
}

void
switch_fini()
{
	struct vnetwork	*v;

	evconnlistener_free(listener);

	while ((v = RB_ROOT(&vnetworks)) != NULL)
		vnetwork_del(v);

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

RB_GENERATE_STATIC(lladdr_tree, lladdr, entry, lladdr_cmp);
RB_GENERATE_STATIC(acl_node_tree, node, entry, node_cmp);
RB_GENERATE_STATIC(tls_peer_tree, tls_peer, entry, tls_peer_cmp);
RB_GENERATE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);
