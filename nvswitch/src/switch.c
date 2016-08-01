/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
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

#include "cert.h"
#include "switch.h"

extern struct event_base	*ev_base;
static struct event		*ev_udplisten;
static struct addrinfo		*ai;
static SSL_CTX			*ctx;
static passport_t		*passport;
static unsigned char		 cookie_secret[16];
static int			 cookie_initialized;

int
certverify_cb(int ok, X509_STORE_CTX *store)
{
	X509		*cert;
	X509_NAME	*name;
	char		buf[256];

	cert = X509_STORE_CTX_get_current_cert(store);
	name = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(name, NID_commonName, buf, 256);

	printf("CN: %s\n", buf);

	return (ok);
}

int
servername_cb(SSL *ssl, int *ad, void *arg)
{
	const char	*name;

	if ((name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) == NULL)
		return SSL_TLSEXT_ERR_NOACK;

	printf(">>> name %s\n", name);

	/* Load the trusted certificate store into our SSL_CTX */
	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	/* Set the certificate and key */
	SSL_use_certificate(ssl, passport->certificate);
	SSL_use_PrivateKey(ssl, passport->keyring);

	return SSL_TLSEXT_ERR_OK;
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
			return 0;
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
		return 0;
	}

	if ((buffer = OPENSSL_malloc(length)) == NULL)
		return 0;

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
		return 0;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), cookie_secret, sizeof(cookie_secret),
	    buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

    return 1;
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
		return 0;

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
		return 0;
	}

	if ((buffer = OPENSSL_malloc(length)) == NULL)
		return 0;

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
		return 0;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), cookie_secret, sizeof(cookie_secret),
	    buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength
	    && memcmp(result, cookie, resultlength) == 0)
		return 1;

    return 0;
}

void
udpclient_cb(int sock, short what, void *arg)
{
	printf("udpclient_cb %d\n", sock);

	SSL	*ssl;
	char	 buf[1500] = {0};
	int	 ret;

	ssl = arg;

	if ((ret = SSL_read(ssl, &buf, sizeof(buf))) < 0) {
		ret = SSL_get_error(ssl, ret);
		fprintf(stderr, "SSL_read: error %d (%d-%d)\n", ret, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
		ERR_print_errors_fp(stderr);
		return;
	}
	fprintf(stderr, "%s %d", buf, ret);
}

void
udplisten_cb(int sock, short what, void *arg)
{
	BIO		*bio = NULL;
	SSL		*ssl = NULL;
	SSL_CTX		*ctx;
	struct event	*ev_udpclient;
	struct sockaddr	 caddr;
	int		 csock = -1;
	int		 flag;
	int		 ret;

	ctx = arg;

	if ((ssl = SSL_new(ctx)) == NULL) {
		warnx("%s:%d", "SSL_new", __LINE__);
		goto error;
	}
	SSL_set_accept_state(ssl);
	SSL_set_verify(ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);

	if ((bio = BIO_new_dgram(sock, BIO_NOCLOSE)) == NULL) {
		warnx("%s:%d", "BIO_new_dgram", __LINE__);
		goto error;
	}
	SSL_set_bio(ssl, bio, bio);

	if ((ret = DTLSv1_listen(ssl, &caddr)) <= 0)
		goto error;

	if ((csock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		warnx("%s:%d", "socket", __LINE__);
		goto error;
	}

	flag = 1;
	if (setsockopt(csock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
		warnx("%s:%d", "setsockopt", __LINE__);
		goto error;
	}

	if (evutil_make_socket_nonblocking(csock) > 0) {
		warn("%s:%d", "evutil_make_socket_nonblocking", __LINE__);
		goto error;
	}

	if (bind(csock, ai->ai_addr, ai->ai_addrlen) < 0) {
		warnx("%s:%d", "bind", __LINE__);
		goto error;
	}

	if (connect(csock, &caddr, sizeof(caddr)) < 0) {
		warn("%s:%d", "connect", __LINE__);
		goto error;
	}

	BIO_set_fd(SSL_get_rbio(ssl), csock, BIO_NOCLOSE);

	if ((ev_udpclient = event_new(ev_base, csock,
	    EV_READ | EV_PERSIST, udpclient_cb, ssl)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
	event_add(ev_udpclient, NULL);

	return;

error:
	SSL_free(ssl);
	//BIO_free(bio);
	close(csock);
}

void
switch_init(json_t *config)
{
	EC_KEY		*ecdh;
	struct addrinfo	 hints;
	const char	*ip;
	const char	*port;
	const char	*cert;
	const char	*pkey;
	const char	*trust_cert;
	int		 status;
	int		 sock;
	int		 flag;

	if (json_unpack(config, "{s:s}", "switch_ip", &ip) < 0)
		err(1, "switch_ip is not present in config");

	if (json_unpack(config, "{s:s}", "switch_port", &port) < 0)
		err(1, "switch_port is not present in config");

	if (json_unpack(config, "{s:s}", "certificate", &cert) < 0)
		err(1, "certificate is not present in config");

	if (json_unpack(config, "{s:s}", "privatekey", &pkey) < 0)
		err(1, "privatekey is not present in config");

	if (json_unpack(config, "{s:s}", "trusted_cert", &trust_cert) < 0)
		err(1, "trusted_cert is not present in config");

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		err(1, "RAND_poll");

	if ((ctx = SSL_CTX_new(DTLSv1_server_method())) == NULL)
		errx(1, "SSL_CTX_new");
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
	SSL_CTX_set_tlsext_servername_callback(ctx, servername_cb);
	SSL_CTX_set_tlsext_servername_arg(ctx, NULL);

	if ((passport = pki_passport_load_from_file(cert, pkey, trust_cert)) == NULL)
		err(1, "pki_passport_load_from_file");

	SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA");

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		err(1, "EC_KEY_new_by_curve_name");

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	EC_KEY_free(ecdh);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		errx(1, "getaddrinfo: %s", gai_strerror(status));

	if ((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
		errx(1, "socket");

	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		errx(1, "setsockopt");

	if (evutil_make_socket_nonblocking(sock) > 0)
		err(1, "evutil_make_socket_nonblocking");

	if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		errx(1, "bind");

	if ((ev_udplisten = event_new(ev_base, sock,
	    EV_READ | EV_PERSIST, udplisten_cb, ctx)) == NULL)
		err(1, "event_new");
	event_add(ev_udplisten, NULL);
}

void
switch_fini()
{
	SSL_CTX_free(ctx);
	freeaddrinfo(ai);
	pki_passport_destroy(passport);
	if (ev_udplisten != NULL)
		evsignal_del(ev_udplisten);
	event_base_free(ev_base);

	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}
