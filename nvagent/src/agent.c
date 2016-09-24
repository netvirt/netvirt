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
udpclient_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	(void)arg;

	printf("udpclient_cb %d\n", sock);

	SSL     *ssl;
	int      ret;
	char     buf[1500] = {0};

        ssl = arg;

        if ((ret = SSL_read(ssl, &buf, sizeof(buf))) < 0) {
                ret = SSL_get_error(ssl, ret);
                fprintf(stderr, "SSL_read: error %d (%d-%d)\n", ret, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
                ERR_print_errors_fp(stderr);
                return;
        }
        SSL_write(ssl, "hello", 4);
        fprintf(stderr, "%s %d", buf, ret);
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
	int		 ret;
	const char	*ip = "127.0.0.1";
	const char	*port = "9090";
	const char	*cert = "/etc/netvirt/certs/netvirt-app-cert.pem";
	const char	*pkey = "/etc/netvirt/certs/netvirt-app-privkey.pem";
	const char	*trust_cert = "/etc/netvirt/certs/netvirt-ctrler-cert.pem";

	SSL_library_init();
	SSL_load_error_strings();

	if (!RAND_poll())
		err(1, "%s:%d", "RAND_poll", __LINE__);

	if ((ctx = SSL_CTX_new(DTLSv1_client_method())) == NULL)
		errx(1, "%s:%d", "SSL_CTX_new", __LINE__);

	if ((passport = pki_passport_load_from_file(cert, pkey, trust_cert)) == NULL)
		err(1, "%s:%d", "pki_passport_load_from_file", __LINE__);

	/* Load the trusted certificate store into our SSL_CTX */
	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	/* Set the certificate and key */
	SSL_CTX_use_certificate(ctx, passport->certificate);
	SSL_CTX_use_PrivateKey(ctx, passport->keyring);

	if ((ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA")) == 0)
		err(1, "%s:%d", "SSL_CTX_set_cipher_list", __LINE__);

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

	if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		warn("%s:%d", "connect", __LINE__);

	if ((ssl = SSL_new(ctx)) == NULL)
		warnx("%s:%d", "SSL_new", __LINE__);

	SSL_set_tlsext_host_name(ssl, "test");
	SSL_set_verify(ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);

	if ((bio = BIO_new_dgram(sock, BIO_NOCLOSE)) == NULL)
		warnx("%s:%d", "BIO_new_dgram", __LINE__);

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ai->ai_addr);

	SSL_set_bio(ssl, bio, bio);

	if (evutil_make_socket_nonblocking(sock) > 0)
		err(1, "%s:%d", "evutil_make_socket_nonblocking", __LINE__);

	char buf[1500] = {0};

	SSL_set_connect_state(ssl);
	//if ((ret = SSL_connect(ssl)) <= 0) {
//        if ((ret = SSL_read(ssl, &buf, sizeof(buf))) < 0) {
        if ((ret = SSL_write(ssl, "hello", 4)) < 0) {
		ret = SSL_get_error(ssl, ret);
		fprintf(stderr, "SSL_read: error %d (%d-%d)\n", ret, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
		ERR_print_errors_fp(stderr);
		warn("ssl_connect");
	}

	if ((ev_udpclient = event_new(ev_base, sock,
	    EV_READ | EV_PERSIST, udpclient_cb, ssl)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
	event_add(ev_udpclient, NULL);

	return (0);
}

void
agent_fini()
{

}

