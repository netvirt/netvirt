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
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <sys/socket.h>
	#include <netdb.h>
	#include <unistd.h>
#endif

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <jansson.h>

#include <inet.h>
#include <pki.h>
#include <log.h>
#include <tapcfg.h>

#include "agent.h"

enum nv_type {
	NV_KEEPALIVE		= 0,
	NV_L2		 	= 1,
};

struct nv_hdr {
	uint16_t		 length;
	uint16_t		 type;
	char			 value[];
} __attribute__((__packed__));

struct vlink {
	passport_t		*passport;
	tapcfg_t		*tapcfg;
	struct tls_peer		*peer;
	struct event		*ev_reconnect;
	struct event		*ev_keepalive;
	struct event		*ev_readagain;
	int			 tapfd;
	char			*addr;
};

struct tls_peer {
	SSL			*ssl;
	SSL_CTX			*ctx;
	socklen_t		 ss_len;
	struct bufferevent	*bev;
	struct sockaddr_storage	 ss;
	struct vlink		*vlink;
	int			 sock;
	int			 status;
};

struct eth_hdr {
	uint8_t		dmac[6];
	uint8_t		smac[6];
	uint16_t	ethertype;
} __attribute__((packed));

struct packets {
	int			 len;
	uint8_t			 buf[5000];
	TAILQ_ENTRY(packets)	 entries;
};

struct event_base		*ev_base;
static struct event		*ev_iface;
static struct eth_hdr		 eth_ping;
static struct network		*netcf;
static struct vlink		*vlink;

TAILQ_HEAD(tailhead, packets)	 tailq_head;

static void		 tls_peer_free(struct tls_peer *);
static struct tls_peer	*tls_peer_new();

static SSL_CTX		*ctx_init();

static int	 	 cert_verify_cb(int, X509_STORE_CTX *);
static void		 info_cb(const SSL *, int, int);

static void	 	 iface_cb(int, short, void *);

static void		 vlink_free(struct vlink *);
static void		 vlink_keepalive(evutil_socket_t, short, void *);
static void		 vlink_reset(evutil_socket_t, short, void *);
static void		 vlink_reconnect(struct vlink *);
static int		 vlink_connect(struct tls_peer *, struct vlink *);
static int		 vlink_send(struct tls_peer *, enum nv_type, const void *, size_t);

static void		 peer_event_cb(struct bufferevent *, short, void *);
static void		 peer_read_cb(struct bufferevent *, void *);

void
vlink_free(struct vlink *v)
{
	if (v == NULL)
		return;

	pki_passport_destroy(v->passport);
	event_free(v->ev_reconnect);
	event_free(v->ev_keepalive);
	tls_peer_free(v->peer);
	free(v->addr);
	free(v);
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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined (LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
	// Remove the reference to the store, otherwise OpenSSL will try to free it.
	// OpenSSL 1.0.1 doesn't have the function X509_STORE_up_ref().
	p->ctx->cert_store = NULL;
#endif
	SSL_CTX_free(p->ctx);

	free(p);
}

struct tls_peer *
tls_peer_new()
{
	struct tls_peer		*p;

	if ((p = malloc(sizeof(*p))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	p->ssl = NULL;
	p->ctx = NULL;
	p->ss_len = 0;
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
vlink_connect(struct tls_peer *p, struct vlink *v)
{
	struct addrinfo	 	 hints;
	struct addrinfo		*res = NULL;
	struct timeval		 tv;
	EC_KEY			*ecdh = NULL;
	int			 err, ret;
	const char		*port = "9090";

	ret = -1;

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (event_add(v->ev_reconnect, &tv) < 0) {
		log_warn("%s: event_add", __func__);
		goto out;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((err = getaddrinfo(v->addr, port, &hints, &res)) < 0) {
		log_warnx("%s: getaddrinfo %s", __func__, gai_strerror(err));
		goto out;
	}

	if ((p->sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		log_warnx("%s: socket", __func__);
		goto out;
	}

#ifndef _WIN32
	int flag = 1;
	if (setsockopt(p->sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(p->sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		log_warn("%s: setsockopt", __func__);
		goto out;
	}
#endif

	if (evutil_make_socket_nonblocking(p->sock) > 0) {
		log_warnx("%s: evutil_make_socket_nonblocking", __func__);
		goto out;
	}

	SSL_set_tlsext_host_name(p->ssl, v->passport->certinfo->network_uid);

	SSL_CTX_set_cert_store(p->ctx, v->passport->cacert_store);
	X509_STORE_up_ref(v->passport->cacert_store);

	SSL_set_SSL_CTX(p->ssl, p->ctx);

	if ((SSL_use_certificate(p->ssl, v->passport->certificate)) != 1) {
		log_warnx("%s: SSL_CTX_use_certificate", __func__);
		goto out;
	}

	if ((SSL_use_PrivateKey(p->ssl, v->passport->keyring)) != 1) {
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

	if (bufferevent_socket_connect(p->bev, res->ai_addr, res->ai_addrlen)
	    < 0) {
		log_warnx("%s: bufferevent_socket_connected", __func__);
		goto out;
	}

	ret = 0;

out:
	EC_KEY_free(ecdh);
	freeaddrinfo(res);

	return (ret);
}

SSL_CTX *
ctx_init()
{
	EC_KEY	*ecdh = NULL;
	SSL_CTX	*ctx = NULL;
	int	 err;

	err = -1;

	if ((ctx = SSL_CTX_new(TLSv1_2_method())) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		goto out;
	}

	if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384") != 1) {
		log_warnx("%s: SSL_CTX_set_cipher_list", __func__);
		goto out;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("%s: EC_KEY_new_by_curve_name", __func__);
		goto out;
	}

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);

	SSL_CTX_set_verify(ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_cb);

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
cert_verify_cb(int ok, X509_STORE_CTX *store)
{
	X509		*cert;
	X509_NAME	*name;
	char		 buf[256];

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

	printf("connected !\n");
}

#if defined(_WIN32) || defined(__APPLE__)
void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	struct timeval	 tv;
	struct vlink	*vlink = arg;
	struct packets	 pkt;
	int		 ret;

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	ret = tapcfg_wait_readable(vlink->tapcfg, 0);
	if (ret == 0) {
		tv.tv_sec = 0;
		tv.tv_usec = 10000;
		goto out;
	}

	pkt.len = tapcfg_read(vlink->tapcfg, pkt.buf, sizeof(pkt.buf));

	if (vlink->peer != NULL && vlink->peer->status == 1) {
		ret = vlink_send(vlink->peer, NV_L2, pkt.buf, pkt.len);
		if (ret < 0) {
			vlink_reconnect(vlink);
			return;
		}
	}

out:
	evtimer_add(ev_iface, &tv);

	return;
}
#else
void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;

	struct vlink		*vlink = arg;
	int			 ret;
	uint8_t			 buf[5000] = {0};

	vlink = arg;

	ret = tapcfg_read(vlink->tapcfg, buf, sizeof(buf));
	// XXX check ret

	if (vlink->peer != NULL && vlink->peer->status == 1)
		vlink_send(vlink->peer, NV_L2, buf, ret);
}
#endif

void
vlink_readagain(evutil_socket_t fd, short event, void *arg)
{
	(void)fd;
	(void)event;

	struct vlink	*v = arg;

	peer_read_cb(v->peer->bev, v->peer);
}

void
vlink_keepalive(evutil_socket_t fd, short event, void *arg)
{
	(void)event;
	(void)fd;
	struct vlink	*vlink = arg;

	vlink_send(vlink->peer, NV_KEEPALIVE, NULL, 0);
}

void
vlink_reset(evutil_socket_t fd, short what, void *arg)
{
	struct vlink	*vlink = arg;
	(void)fd;
	(void)what;

	printf("vlink reset\n");
	event_del(vlink->ev_reconnect);
	event_del(vlink->ev_keepalive);
	if (vlink->peer != NULL) {
		tls_peer_free(vlink->peer);
		vlink->peer = NULL;
	}

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
	vlink_reconnect(vlink);
	return;
}

void
vlink_reconnect(struct vlink *vlink)
{
	struct timeval	wait_sec = {5, 0};

	printf("reconnect...\n");
	event_del(vlink->ev_reconnect);
	event_del(vlink->ev_keepalive);

	if (vlink->peer && vlink->peer->bev)
		bufferevent_disable(vlink->peer->bev, EV_READ | EV_WRITE);

	if (event_base_once(ev_base, -1, EV_TIMEOUT,
	    vlink_reset, vlink, &wait_sec) < 0)
		log_warnx("%s: event_base_once", __func__);
}

int
vlink_send(struct tls_peer *p, enum nv_type type, const void *data,
    size_t size)
{
	struct nv_hdr	 hdr;

	hdr.type = htons(type);
	hdr.length = htons(size + sizeof(hdr.type));
	if (bufferevent_write(p->bev, &hdr, sizeof(hdr)) < 0 ||
	    (size != 0 &&
	    bufferevent_write(p->bev, data, size) < 0) ||
	    bufferevent_flush(p->bev, EV_WRITE, BEV_FLUSH) < 0)
		return (-1);

	return (0);
}

void
peer_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct tls_peer	*p = arg;
	struct timeval	 tv;
	unsigned long	 e;

	printf("event cb\n");

	if (events & (BEV_EVENT_READING)) {
		printf("timeout reading\n");
	}

	if (events & (BEV_EVENT_WRITING)) {
		printf("timeout writing\n");
	}

	if (events & BEV_EVENT_TIMEOUT) {
		printf("timeout\n");
	}

	if (events & BEV_EVENT_ERROR) {
		printf("bev event error\n");
		printf("err: %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

	}

	if (events & BEV_EVENT_EOF) {
		printf("bev eof\n");
	}

	if (events & BEV_EVENT_CONNECTED) {

		printf("connected?\n");
		p->status = 1;
		event_del(p->vlink->ev_reconnect);

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		bufferevent_set_timeouts(p->bev, &tv, NULL);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if (event_add(p->vlink->ev_keepalive, &tv) < 0) {
			log_warn("%s: event_add", __func__);
		}

	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT | BEV_EVENT_EOF)) {
		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			log_warnx("%s: TLS error: %s", __func__,
			    ERR_reason_error_string(e));
		}
		vlink_reconnect(p->vlink);
	}

	return;
}

void
peer_read_cb(struct bufferevent *bev, void *arg)
{
	struct timeval		 tv;
	struct evbuffer		*in;
	struct tls_peer		*p = arg;
	const struct nv_hdr	*hdr;
	int			 n;
	size_t			 payload;

	in = bufferevent_get_input(bev);

	if (evbuffer_get_length(in) < sizeof(*hdr))
		return;
	if ((hdr = (const struct nv_hdr *)evbuffer_pullup(in,
	    sizeof(*hdr))) == NULL)
		goto error;

	if (ntohs(hdr->length) < sizeof(hdr->type))
		goto error;
	payload = ntohs(hdr->length) - sizeof(hdr->type);

	if (evbuffer_get_length(in) < sizeof(*hdr) + payload)
		return;
	if ((hdr = (const struct nv_hdr *)evbuffer_pullup(in,
	    sizeof(*hdr) + payload)) == NULL)
		goto error;

	switch (ntohs(hdr->type)) {
	case NV_KEEPALIVE:
		break;
	case NV_L2:
		n = tapcfg_write(p->vlink->tapcfg, (uint8_t *)&hdr->value, payload);
		break;
	default:
		break;
	}

	if (evbuffer_drain(in,
	    sizeof(*hdr) - sizeof(hdr->type) + ntohs(hdr->length)) < 0)
		goto error;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	if (evtimer_add(vlink->ev_readagain, &tv) < 0)
		goto error;

	return;

error:
	// XXX
	printf("should disconnect from server\n");
	return;

}

int
switch_init(tapcfg_t *tapcfg, int tapfd, const char *vswitch_addr, const char *ipaddr,
    const char *network_name)
{
	eth_ping.ethertype = htons(0x9000);

	if ((vlink = malloc(sizeof(struct vlink))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto cleanup;
	}
	vlink->passport = NULL;
	vlink->tapcfg = NULL;
	vlink->peer = NULL;
	vlink->addr = NULL;

	vlink->tapcfg = tapcfg;
	vlink->tapfd = tapfd;

	if ((vlink->ev_reconnect = event_new(ev_base, 0,
	    EV_TIMEOUT, vlink_reset, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);

	if ((vlink->ev_keepalive = event_new(ev_base, 0,
	    EV_TIMEOUT | EV_PERSIST , vlink_keepalive, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);

	if ((vlink->ev_readagain = event_new(ev_base, 0,
	    EV_TIMEOUT, vlink_readagain, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);

	if ((vlink->addr = strdup(vswitch_addr)) == NULL) {
		log_warn("%s: strdup", __func__);
		goto cleanup;
	}

	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_IPV4_UP);
	// XXX netmask not always 24
	tapcfg_iface_set_ipv4(tapcfg, ipaddr, 24);

	if ((netcf = ndb_network(network_name)) == NULL) {
		log_warnx("%s: the network doesn't exist: %s",
		    __func__, network_name);
		goto cleanup;
	}

	if ((vlink->passport =
	    pki_passport_load_from_memory(netcf->cert, netcf->pvkey, netcf->cacert)) == NULL) {
		log_warnx("%s: pki_passport_load_from_memory", __func__);
		goto cleanup;
	}

#if defined(_WIN32) || defined(__APPLE__)
	if ((ev_iface = event_new(ev_base, 0,
		EV_TIMEOUT, iface_cb, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);

	event_active(ev_iface, EV_TIMEOUT, 0);
#else
	if ((ev_iface = event_new(ev_base, tapfd,
	    EV_READ | EV_PERSIST, iface_cb, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);

	event_add(ev_iface, NULL);
#endif


	event_active(vlink->ev_reconnect, EV_TIMEOUT, 0);

	return (0);

cleanup:

	return (-1);
}

void
switch_fini(void)
{
	vlink_free(vlink);
	event_free(ev_iface);
}
