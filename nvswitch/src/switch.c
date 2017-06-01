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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/event.h>

#include <log.h>
#include <pki.h>

#include "switch.h"
#include "vnetwork.h"

enum dtls_state {
	DTLS_LISTEN,
	DTLS_ACCEPT,
	DTLS_ESTABLISHED
};

struct dtls_peer {
	RB_ENTRY(dtls_peer)	 entry;
	struct sockaddr_storage  ss;
	struct event		*timer;
	enum dtls_state		 state;
	socklen_t		 ss_len;
	SSL			*ssl;
};

RB_HEAD(dtls_peer_tree, dtls_peer);

static struct dtls_peer_tree	 dtls_peers;
static EC_KEY			*ecdh;
static DH			*dh;
static SSL_CTX			*ctx;
static struct event		*ev_udplisten;
static struct addrinfo		*ai;
static int			 cookie_initialized;
static unsigned char		 cookie_secret[16];

static int		 generate_cookie(SSL *, unsigned char *, unsigned int *);
static int		 verify_cookie(SSL *, unsigned char *, unsigned int);
static int		 cert_verify_cb(int, X509_STORE_CTX *);
static struct dtls_peer	*dtls_peer_new(int);
static void		 dtls_peer_free(struct dtls_peer *);
static int		 dtls_peer_process(struct dtls_peer *);
static void		 dtls_peer_timeout_cb(int, short, void *);
static int		 dtls_peer_cmp(const struct dtls_peer *,
			    const struct dtls_peer *);
RB_PROTOTYPE_STATIC(dtls_peer_tree, dtls_peer, entry, dtls_peer_cmp);

int
dtls_peer_cmp(const struct dtls_peer *a, const struct dtls_peer *b)
{

	if (a->ss_len < b->ss_len)
		return (-1);
	if (b->ss_len > b->ss_len)
		return (1);
	return (memcmp(&a->ss, &b->ss, a->ss_len));
}

struct dtls_peer *
dtls_peer_new(int sock)
{
	BIO			*bio = NULL;
	struct dtls_peer	*p = NULL;

	if ((p = malloc(sizeof(*p))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}

	if ((p->ssl = SSL_new(ctx)) == NULL) {
		log_warnx("%s: SSL_new", __func__);
		goto error;
	}

	SSL_set_accept_state(p->ssl);
	SSL_set_verify(p->ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	    cert_verify_cb);

	if ((bio = BIO_new_dgram(sock, BIO_NOCLOSE)) == NULL) {
		log_warnx("%s: BIO_new_dgram", __func__);
		goto error;
	}

	SSL_set_bio(p->ssl, bio, bio);

	p->state = DTLS_LISTEN;
	p->timer = evtimer_new(ev_base, dtls_peer_timeout_cb, p);

	return (p);

error:
	dtls_peer_free(p);
	return (NULL);
}

void
dtls_peer_free(struct dtls_peer *p)
{
	SSL_free(p->ssl);
	free(p);
}

int
dtls_peer_process(struct dtls_peer *p)
{
	struct timeval		 tv;
	struct sockaddr		 caddr;
	enum dtls_state		 next_state;
	int			 ret;
	char			 buf[1500] = {0};

	switch (p->state) {
	case DTLS_LISTEN:
		ret = DTLSv1_listen(p->ssl, &caddr);
		next_state = DTLS_ACCEPT;
		break;

	case DTLS_ACCEPT:
		ret = SSL_accept(p->ssl);
		next_state = DTLS_ESTABLISHED;
		break;

	case DTLS_ESTABLISHED:
		ret = SSL_read(p->ssl, buf, sizeof(buf));
		next_state = DTLS_ESTABLISHED;
		break;

	default:
		log_warnx("invalid DTLS peer state");
		return (-1);
	}

	switch (SSL_get_error(p->ssl, ret)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
		if (DTLSv1_get_timeout(p->ssl, &tv) == 1 &&
		    evtimer_add(p->timer, &tv) < 0)
			return (-1);
		return (0);
	default:
		// XXX logs... and disconnect
		return (-1);
	}

	p->state = next_state;

	return (0);
}

void
dtls_peer_timeout_cb(int fd, short event, void *arg)
{
	struct dtls_peer	*p = arg;

	DTLSv1_handle_timeout(p->ssl);

	if (dtls_peer_process(p) < 0) {
		RB_REMOVE(dtls_peer_tree, &dtls_peers, p);
		dtls_peer_free(p);
	}
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

int
servername_cb(SSL *ssl, int *ad, void *arg)
{
	SSL_CTX		*ctx;
	struct vnetwork	*vnet;
	const char	*servername;

	if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
	    == NULL) {
		log_warnx("%s: no servername received", __func__);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}

	printf(">>> name %s\n", servername);

	if ((vnet = vnetwork_lookup(servername)) == NULL) {
		printf("vnet is NULL!\n");
	}

	if (vnet->ctx == NULL) {

		if ((ctx = SSL_CTX_new(DTLSv1_method())) == NULL)
			log_warnx("%s: SSL_CTX_new", __func__);

		SSL_CTX_set_read_ahead(ctx, 1);

		SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

		SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
		SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
		SSL_CTX_set_tlsext_servername_callback(ctx, servername_cb);
		SSL_CTX_set_tlsext_servername_arg(ctx, NULL);

		if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA") == 0)
			log_warnx("%s: SSL_CTX_set_cipher_list", __func__);

		/* Load the trusted certificate store into our SSL_CTX */
		SSL_CTX_set_cert_store(ctx, vnet->passport->cacert_store);

		vnet->ctx = ctx;
	} else {
		ctx = vnet->ctx; /* XXX free me */
	}

	SSL_set_SSL_CTX(ssl, ctx);

	/* Set the certificate and key */
	SSL_use_certificate(ssl, vnet->passport->certificate);
	SSL_use_PrivateKey(ssl, vnet->passport->keyring);

	return (SSL_TLSEXT_ERR_OK);
}

/* generate_cookie and verify_cookie
 * taken from openssl apps/s_cb.c
 */
int
generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char	*buffer;
	unsigned char	 result[EVP_MAX_MD_SIZE];
	unsigned int	 length, resultlength;

	union {
		struct sockaddr sa;
		struct sockaddr_in s4;
#if OPENSSL_USE_IPV6
		struct sockaddr_in6 s6;
#endif
	} peer;

	/* Initialize a random secret */
	if (cookie_initialized == 0) {
		if (RAND_bytes(cookie_secret, sizeof(cookie_secret)) <= 0)
			return (0);
		cookie_initialized = 1;
	}

	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.sa.sa_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		length += sizeof(peer.s4.sin_port);
		break;
#if OPENSSL_USE_IPV6
	case AF_INET6:
		length += sizeof(struct in6_addr);
		length += sizeof(peer.s6.sin6_port);
		break;
#endif
	default:
		return (0);
	}

	if ((buffer = OPENSSL_malloc(length)) == NULL)
		return (0);

	switch (peer.sa.sa_family) {
	case AF_INET:
		memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
		memcpy(buffer + sizeof(peer.s4.sin_port),
		    &peer.s4.sin_addr, sizeof(struct in_addr));
		break;
#if OPENSSL_USE_IPV6
	case AF_INET6:
		memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
		memcpy(buffer + sizeof(peer.s6.sin6_port),
		    &peer.s6.sin6_addr, sizeof(struct in6_addr));
		break;
#endif
	default:
		return (0);
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), cookie_secret, sizeof(cookie_secret),
	    buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

    return (1);
}

int
verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char	*buffer;
	unsigned char	 result[EVP_MAX_MD_SIZE];
	unsigned int	 length, resultlength;

	union {
		struct sockaddr sa;
		struct sockaddr_in s4;
#if OPENSSL_USE_IPV6
		struct sockaddr_in6 s6;
#endif
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (cookie_initialized == 0)
		return (0);

	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.sa.sa_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		length += sizeof(peer.s4.sin_port);
		break;
#if OPENSSL_USE_IPV6
	case AF_INET6:
		length += sizeof(struct in6_addr);
		length += sizeof(peer.s6.sin6_port);
		break;
#endif
	default:
		return (0);
	}

	if ((buffer = OPENSSL_malloc(length)) == NULL)
		return (0);

	switch (peer.sa.sa_family) {
	case AF_INET:
		memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
		memcpy(buffer + sizeof(peer.s4.sin_port),
		    &peer.s4.sin_addr, sizeof(struct in_addr));
		break;
#if OPENSSL_USE_IPV6
	case AF_INET6:
		memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
		memcpy(buffer + sizeof(peer.s6.sin6_port),
		    &peer.s6.sin6_addr, sizeof(struct in6_addr));
		break;
#endif
	default:
		return (0);
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), cookie_secret, sizeof(cookie_secret),
	    buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength
	    && memcmp(result, cookie, resultlength) == 0)
		return (1);

    return (0);
}

void
udplisten_cb(int sock, short what, void *ctx)
{
	struct dtls_peer	*p, needle;

	needle.ss_len = sizeof(struct dtls_peer);
	char s[INET6_ADDRSTRLEN];

	recvfrom(sock, NULL, 0, MSG_PEEK, (struct sockaddr *)&needle.ss,
	    &needle.ss_len);

	printf("got packet from %s :: %d\n",
		inet_ntop(needle.ss.ss_family,
		&((struct sockaddr_in*)&needle.ss)->sin_addr, s, sizeof(s)),
		ntohs(&((struct sockaddr_in*)&needle.ss)->sin_port));

	if ((p = RB_FIND(dtls_peer_tree, &dtls_peers, &needle)) == NULL) {
		if ((p = dtls_peer_new(sock)) == NULL)
			goto error;
		else {
			p->ss = needle.ss;
			p->ss_len = needle.ss_len;
			RB_INSERT(dtls_peer_tree, &dtls_peers, p);
		}
	}

	if (dtls_peer_process(p) < 0)
		goto error;
	return;

error:
	dtls_peer_free(p);
	return;
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

        dh = DH_new();
        if (dh == NULL) {
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



void
switch_init(json_t *config)
{
	struct addrinfo	 hints;
	int		 status;
	int		 sock;
	int		 flag;
	const char	*ip;
	const char	*port;
	const char	*cert;
	const char	*pkey;
	const char	*cacert;

	if (json_unpack(config, "{s:s}", "switch_ip", &ip) < 0)
		fatalx("%s: switch_ip not found in config", __func__);

	if (json_unpack(config, "{s:s}", "switch_port", &port) < 0)
		fatalx("%s: switch_port not found config", __func__);

	if (json_unpack(config, "{s:s}", "cert", &cert) < 0)
		fatalx("%s: 'cert' not found in config", __func__);

	if (json_unpack(config, "{s:s}", "pvkey", &pkey) < 0)
		fatalx("%s: 'pvkey' not found in config", __func__);

	if (json_unpack(config, "{s:s}", "cacert", &cacert) < 0)
		fatalx("%s: 'cacert' not found in config", __func__);

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		fatalx("%s: RAND_poll", __func__);

	if ((ctx = SSL_CTX_new(DTLSv1_method())) == NULL)
		fatalx("%s: SSL_CTX_new", __func__);

	SSL_CTX_set_read_ahead(ctx, 1);

	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
	SSL_CTX_set_tlsext_servername_callback(ctx, servername_cb);
	SSL_CTX_set_tlsext_servername_arg(ctx, NULL);

	dh = get_dh_1024();

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		fatalx("%s: EC_KEY_new_by_curve_name", __func__);

	SSL_CTX_set_tmp_dh(ctx, dh);

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);

	if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA") == 0)
		fatalx("%s: SSL_CTX_set_cipher_list", __func__);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		fatalx("%s: getaddrinfo: %s", __func__, gai_strerror(status));

	if ((sock = socket(ai->ai_family, ai->ai_socktype,
	    ai->ai_protocol)) < 0)
		fatal("%s: socket", __func__);

	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		fatal("%s: setsockopt", __func__);

	if (evutil_make_socket_nonblocking(sock) > 0)
		fatalx("%s: evutil_make_socket_nonblocking", __func__);

	if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		fatal("%s: bind", __func__);

	if ((ev_udplisten = event_new(ev_base, sock,
	    EV_READ | EV_PERSIST, udplisten_cb, ctx)) == NULL)
		fatal("%s: event_new", __func__);
	event_add(ev_udplisten, NULL);
}

void
switch_fini()
{
	SSL_CTX_free(ctx);
	freeaddrinfo(ai);

	EC_KEY_free(ecdh);
	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

RB_GENERATE_STATIC(dtls_peer_tree, dtls_peer, entry, dtls_peer_cmp);
