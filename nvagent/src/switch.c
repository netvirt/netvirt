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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/event.h>

#include <jansson.h>

#include <pki.h>
#include <tapcfg.h>

#include "agent.h"

enum dtls_state {
	DTLS_CONNECT,
	DTLS_ESTABLISHED
};

struct dtls_peer {
	struct event	*handshake_timer;
	struct event	*ping_timer;
	enum dtls_state	 state;
	SSL		*ssl;
	tapcfg_t	*tapcfg;
	int		 tapfd;
	int		 sock;
};

struct eth_hdr {
	uint8_t		dmac[6];
	uint8_t		smac[6];
	uint16_t	ethertype;
} __attribute__((packed));

static SSL_CTX			*ctx;
static passport_t		*passport;
static struct addrinfo		*ai;
struct event_base		*ev_base;
struct dtls_peer		 switch_peer;
struct eth_hdr			 eth_ping;

static int	 certverify_cb(int, X509_STORE_CTX *);
static void	 dtls_peer_free(struct dtls_peer *);
static void	 dtls_handshake_timeout_cb(int, short, void *);
static int	 dtls_handle(struct dtls_peer *);
static void	 iface_cb(int, short, void *);
static void	 udpclient_cb(int, short, void *);

int
certverify_cb(int ok, X509_STORE_CTX *store)
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
dtls_peer_free(struct dtls_peer *p)
{
	(void)p;
}

void
ping_timeout_cb(int fd, short event, void *arg)
{
	(void)event;
	(void)fd;

	SSL	*ssl = arg;

	printf("ping timeout !\n");
	SSL_write(ssl, (void *)&eth_ping, sizeof(struct eth_hdr));
}

void
info_cb(const SSL *ssl, int where, int ret)
{
	(void)ret;

	struct dtls_peer	*p;
	struct timeval		 tv;

	if ((where & SSL_CB_HANDSHAKE_DONE) == 0)
		return;

	p = SSL_get_app_data(ssl);

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	p->ping_timer = event_new(ev_base, -1, EV_TIMEOUT | EV_PERSIST,
	    ping_timeout_cb, (SSL *)ssl);
	event_add(p->ping_timer, &tv);

	printf("connected !\n");
}

void
dtls_handshake_timeout_cb(int fd, short event, void *arg)
{
	(void)fd;
	(void)event;

	struct dtls_peer	*p = arg;

	DTLSv1_handle_timeout(p->ssl);

	if (dtls_handle(p) < 0) {
		dtls_peer_free(p);
	}
}

int
dtls_handle(struct dtls_peer *p)
{
	printf("dtls handle\n");
	struct timeval	tv;
	enum dtls_state	next_state;
	int		ret;
	char		buf[5000] = {0};

	for (;;) {

		switch (p->state) {
		case DTLS_CONNECT:
			ret = SSL_do_handshake(p->ssl);
			next_state = DTLS_ESTABLISHED;
			break;

		case DTLS_ESTABLISHED:
			ret = SSL_read(p->ssl, buf, sizeof(buf));
			// XXX check ret
			next_state = DTLS_ESTABLISHED;
			if (ret > 0) {
				ret = tapcfg_write(p->tapcfg, buf, ret);
				// XXX check ret
				return (0);
			}
			break;

		default:
			fprintf(stderr, "%s: invalid DTLS peer state\n", __func__);
			return (-1);
		}

		switch (SSL_get_error(p->ssl, ret)) {
		case SSL_ERROR_NONE:
			break;

		case SSL_ERROR_WANT_WRITE:
			return (0);

		case SSL_ERROR_WANT_READ:
			if (DTLSv1_get_timeout(p->ssl, &tv) == 1 &&
			    evtimer_add(p->handshake_timer, &tv) < 0) {
				return (-1);
			}
			return (0);

		default:
			fprintf(stderr, "%s: ssl error\n", __func__);
			return (-1);
		}

		p->state = next_state;
	}

	return (0);
}

void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;

	struct dtls_peer	*p = arg;
	int			 ret;
	uint8_t			 buf[5000] = {0};

	p = arg;

	printf("iface cb\n");
	ret = tapcfg_read(p->tapcfg, buf, sizeof(buf));
	// XXX check ret

	if (p->state == DTLS_ESTABLISHED) {
		ret = SSL_write(p->ssl, buf, ret);
		// XXX check ret
	}
}

void
udpclient_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	(void)arg;

	struct dtls_peer	*p = arg;

	if (what&EV_TIMEOUT || dtls_handle(p) < 0)
		goto error;

	return;

error:
	dtls_peer_free(p);
}

int
switch_connect(const char *vswitch_addr, const char *network_name)
{
	BIO			*bio = NULL;
	EC_KEY			*ecdh;
	struct timeval		timeout = {5, 0};
	struct event		*ev_udpclient;
	struct addrinfo	 	hints;
	struct dtls_peer	*p;
	struct network		*netcf;
	int			 status;
	int			 flag;
	int			 ret;
	const char		*port = "9090";

	printf("Connecting...\n");

	p = &switch_peer;
	p->state = DTLS_CONNECT;
	p->handshake_timer = evtimer_new(ev_base, dtls_handshake_timeout_cb, p);

	if ((netcf = ndb_network(network_name)) == NULL) {
		fprintf(stderr, "%s: The network specified doesn't exist: %s\n",
		    __func__, network_name);
		return (-1);
	}

	if ((passport = pki_passport_load_from_memory(netcf->cert, netcf->pvkey, netcf->cacert))
	    == NULL)
		err(1, "%s: pki_passport_load_from_memory", __func__);

	SSL_library_init();
	SSL_load_error_strings();

	if (!RAND_poll())
		err(1, "%s: RAND_poll", __func__);

	if ((ctx = SSL_CTX_new(DTLSv1_client_method())) == NULL)
		errx(1, "%s: SSL_CTX_new", __func__);

	SSL_CTX_set_read_ahead(ctx, 1);

	SSL_CTX_set_cert_store(ctx, passport->cacert_store);
	SSL_CTX_use_certificate(ctx, passport->certificate);
	SSL_CTX_use_PrivateKey(ctx, passport->keyring);

	if ((ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA")) == 0)
		err(1, "%s: SSL_CTX_set_cipher_list", __func__);

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		err(1, "%s: EC_KEY_new_by_curve_name", __func__);

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	EC_KEY_free(ecdh);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(vswitch_addr, port, &hints, &ai)) != 0)
		errx(1, "%s: getaddrinfo %s", gai_strerror(status), __func__);

	if ((p->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
		errx(1, "%s: socket", __func__);

#ifndef WIN32
	flag = 1;
	if (setsockopt(p->sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		errx(1, "%s: setsockopt", __func__);
#endif

	if (connect(p->sock, ai->ai_addr, ai->ai_addrlen) < 0)
		warn("%s: connect", __func__);

	if ((p->ssl = SSL_new(ctx)) == NULL || SSL_set_app_data(p->ssl, p) != 1)
		warnx("%s: SSL_new", __func__);

	SSL_set_info_callback(p->ssl, info_cb);
	SSL_set_tlsext_host_name(p->ssl, passport->certinfo->network_uid);
	SSL_set_verify(p->ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);

	if ((bio = BIO_new_dgram(p->sock, BIO_NOCLOSE)) == NULL)
		warnx("%s: BIO_new_dgram", __func__);

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ai->ai_addr);

	SSL_set_bio(p->ssl, bio, bio);

	if (evutil_make_socket_nonblocking(p->sock) > 0)
		err(1, "%s: evutil_make_socket_nonblocking", __func__);

	SSL_set_connect_state(p->ssl);
	SSL_connect(p->ssl);

	if ((ev_udpclient = event_new(ev_base, p->sock,
	    EV_READ|EV_TIMEOUT|EV_PERSIST, udpclient_cb, p)) == NULL)
		warn("%s: event_new", __func__);
	event_add(ev_udpclient, &timeout);

	return (0);
}

void *poke_tap(void *arg)
{
	// XXX add circuit-breaker
	while (1) {
		iface_cb(0, 0, arg);
	}

	return (NULL);
}

int
switch_init(tapcfg_t *tapcfg, int tapfd, const char *vswitch_addr, const char *ipaddr,
    const char *network_name)
{
	struct event		*ev_iface;
	struct dtls_peer	*p;

	eth_ping.ethertype = htons(0x9000);
	p = &switch_peer;

	p->tapcfg = tapcfg;
	p->tapfd = tapfd;

	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_IPV4_UP);
	tapcfg_iface_set_ipv4(tapcfg, ipaddr, 24);


#if defined(_WIN32) || defined(__APPLE__)
	pthread_t thread_poke_tap;
	pthread_attr_t	attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_poke_tap, &attr, poke_tap, (void *)p);
#elif
	if ((ev_iface = event_new(ev_base, tapfd,
	    EV_READ | EV_PERSIST, iface_cb, p)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
	event_add(ev_iface, NULL);
#endif

	switch_connect(vswitch_addr, network_name);

	return (0);	
}

void
agent_fini()
{

}

