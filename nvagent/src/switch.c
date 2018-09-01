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

#if defined(_WIN32) || defined(__APPLE__)
	#include <pthread.h>
#endif

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

struct vlink {
	passport_t		*passport;
	tapcfg_t		*tapcfg;
	struct tls_peer		*peer;
	struct event		*ev_reconnect;
	struct event		*ev_keepalive;
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

#if defined(_WIN32) || defined(__APPLE__)
static pthread_t		 thread_poke_tap;
static pthread_mutex_t		 mutex;
static int			 switch_running = 0;
#endif

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
	struct packets		*pkt;
	struct vlink		*vlink = arg;
	int			 ret;
	pthread_mutex_lock(&mutex);
	while ((pkt = TAILQ_FIRST(&tailq_head)) == NULL) {
		pthread_mutex_unlock(&mutex);
		return;
	}
	pthread_mutex_unlock(&mutex);

	if (vlink->peer != NULL && vlink->peer->status == 1) {
		ret = bufferevent_write(vlink->peer->bev, pkt->buf, pkt->len);
		printf("bev write: ret %d\n", ret);
		if (ret < 0)
			vlink_reconnect(vlink);
	}

	pthread_mutex_lock(&mutex);
	TAILQ_REMOVE(&tailq_head, pkt, entries);
	pthread_mutex_unlock(&mutex);
}

void *poke_tap(void *arg)
{
	struct vlink	*vlink = arg;
	struct packets	*pkt;

	if ((pkt = malloc(sizeof(struct packets))) == NULL) {
		log_warn("%s: malloc", __func__);
		return (NULL);
	}

	while (switch_running) {

		pkt->len = tapcfg_read(vlink->tapcfg, pkt->buf, sizeof(pkt->buf));
		printf("tapcfg_read %d\n", pkt->len);
		// XXX check len

		pthread_mutex_lock(&mutex);
		TAILQ_INSERT_TAIL(&tailq_head, pkt, entries);
		pthread_mutex_unlock(&mutex);
		event_active(ev_iface, EV_TIMEOUT, 0);
	}

	return (NULL);
}
#else
void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;

	struct vlink	*vlink = arg;
	int			 ret;
	uint8_t			 buf[5000] = {0};

	vlink = arg;

	ret = tapcfg_read(vlink->tapcfg, buf, sizeof(buf));
	printf("tapcfg_read: ret %d\n", ret);
	// XXX check ret

	if (vlink->peer != NULL && vlink->peer->status == 1) {
		ret = bufferevent_write(vlink->peer->bev, buf, ret);
		printf("bev write: ret %d\n", ret);
		// XXX check ret
	}
}
#endif

void
vlink_keepalive(evutil_socket_t fd, short event, void *arg)
{
	(void)event;
	(void)fd;
	struct vlink	*vlink = arg;

	printf("keep alive\n");
	bufferevent_write(vlink->peer->bev, (void *)&eth_ping, sizeof(struct eth_hdr));
	bufferevent_flush(vlink->peer->bev, EV_WRITE, BEV_FLUSH);
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

		tv.tv_sec = 10;
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
	struct tls_peer *p = arg;
	int		 n, ret;
	uint8_t		 buf[2000];

	ret = bufferevent_read(bev, buf, sizeof(buf));
	printf("bufferevent read %d\n", ret);

	n = tapcfg_write(p->vlink->tapcfg, buf, ret);
	printf("tapcfg_write: %d\n", n);

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
	TAILQ_INIT(&tailq_head);

	switch_running = 1;

	pthread_attr_t	attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_poke_tap, &attr, poke_tap, vlink);

	if ((ev_iface = event_new(ev_base, 0,
		EV_TIMEOUT, iface_cb, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
#else
	if ((ev_iface = event_new(ev_base, tapfd,
	    EV_READ | EV_PERSIST, iface_cb, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
#endif
	event_add(ev_iface, NULL);

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

#if defined(_WIN32) || defined(__APPLE__)
	switch_running = 0;
	pthread_join(thread_poke_tap, NULL);
#endif
}
