/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <err.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>

#include "cert.h"
#include "agent.h"

static SSL_CTX			*ctx;
static passport_t		*passport;
extern struct event_base	*ev_base;
static struct addrinfo		*ai;
static int			 cookie_initialized;
static unsigned char		 cookie_secret[16];

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

int
servername_cb(SSL *ssl, int *ad, void *arg)
{
	(void)ad;
	(void)arg;
	const char	*name;

	if ((name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) == NULL)
		return (SSL_TLSEXT_ERR_NOACK);

	printf(">>> name %s\n", name);

	/* Load the trusted certificate store into our SSL_CTX */
	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	/* Set the certificate and key */
	SSL_use_certificate(ssl, passport->certificate);
	SSL_use_PrivateKey(ssl, passport->keyring);

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
udpclient_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	(void)arg;
	printf("udpclient_cb\n");
}


int
agent_init(void)
{
	BIO		*bio = NULL;
	SSL		*ssl = NULL;
	EC_KEY		*ecdh;
	struct event	*ev_udpclient;
	struct addrinfo	 hints;
	int		 status;
	int		 sock;
	int		 flag;
	const char	*ip = "127.0.0.1";
	const char	*port = "9090";
	const char	*cert = "/etc/netvirt/certs/netvirt-app-cert.pem";
	const char	*pkey = "/etc/netvirt/certs/netvirt-app-privkey.pem";
	const char	*trust_cert = "/etc/netvirt/certs/netvirt-ctrler-cert.pem";

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		err(1, "%s:%d", "RAND_poll", __LINE__);

	if ((ctx = SSL_CTX_new(DTLSv1_client_method())) == NULL)
		errx(1, "%s:%d", "SSL_CTX_new", __LINE__);

	if ((passport = pki_passport_load_from_file(cert, pkey, trust_cert)) == NULL)
		err(1, "%s:%d", "pki_passport_load_from_file", __LINE__);

	SSL_CTX_set_cipher_list(ctx, "SHA");

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		err(1, "%s:%d", "EC_KEY_new_by_curve_name", __LINE__);

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	EC_KEY_free(ecdh);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		errx(1, "%s:%s:%d", "getaddrinfo", gai_strerror(status), __LINE__);

	if ((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
		errx(1, "%s:%d", "socket", __LINE__);

	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		errx(1, "%s:%d", "setsockopt", __LINE__);


	if (evutil_make_socket_nonblocking(sock) > 0)
		err(1, "%s:%d", "evutil_make_socket_nonblocking", __LINE__);

	if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		warn("%s:%d", "connect", __LINE__);

	if ((ssl = SSL_new(ctx)) == NULL)
		warnx("%s:%d", "SSL_new", __LINE__);

	SSL_set_connect_state(ssl);
/*
	SSL_set_verify(ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);
*/
	if ((bio = BIO_new_dgram(sock, BIO_NOCLOSE)) == NULL)
		warnx("%s:%d", "BIO_new_dgram", __LINE__);

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ai->ai_addr);

	SSL_set_bio(ssl, bio, bio);

	int ret;
	if ((ret = SSL_connect(ssl)) <= 0) {
		ret = SSL_get_error(ssl, ret);
		fprintf(stderr, "SSL_read: error %d (%d-%d)\n", ret, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
		ERR_print_errors_fp(stderr);
		warn("ssl_connect");
	}

	if ((ev_udpclient = event_new(ev_base, sock,
	    EV_READ | EV_PERSIST, udpclient_cb, ssl)) == NULL)
		warn("%s:%d", "event_new", __LINE__);


	return (0);
}

void
agent_fini()
{

}

