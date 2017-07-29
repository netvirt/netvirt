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
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pki.h>
#include <log.h>

#include "agent.h"

struct tls_client {
	struct bufferevent	*bev;
	SSL			*ssl;
	SSL_CTX			*ctx;
};

static void	tls_client_free(struct tls_client *);

void
client_onread_cb(struct bufferevent *bev, void *arg)
{
	printf("on read cb\n");
}

void
client_onevent_cb(struct bufferevent *bev, short events, void *arg)
{
	unsigned long e;

	// XXX load globally
	SSL_load_error_strings();

	if (events & BEV_EVENT_CONNECTED) {

		printf("event connected\n");

	} else if (events & (BEV_EVENT_TIMEOUT | BEV_EVENT_EOF)) {

	} else if (events &  BEV_EVENT_ERROR) {

		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			log_warnx("%s: TLS error: %s", __func__,
			    ERR_reason_error_string(e));
		}
	}
}

struct tls_client *
tls_client_new(const char *hostname, const char *port, passport_t *passport)
{
	struct tls_client	*c = NULL;
	struct addrinfo		*res = NULL;
	struct addrinfo		 hints;
	EC_KEY			*ecdh = NULL;
	int			 fd = -1;
	int			 flag;
	int			 ret;

	if ((c = malloc(sizeof(*c))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto cleanup;
	}
	c->ssl = NULL;
	c->ctx = NULL;
	c->bev = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo(hostname, port, &hints, &res)) < 0) {
		log_warnx("%s: getaddrinfo %s", __func__, gai_strerror(ret));
		goto cleanup;
	}

	if ((fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_warnx("%s: socket", __func__);
		goto cleanup;
	}

	flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
                log_warn("%s: setsockopt", __func__);
                goto cleanup;
        }

	if (evutil_make_socket_nonblocking(fd) < 0) {
		log_warnx("%s: evutil_make_socket_nonblocking", __func__);
		goto cleanup;
	}

	if ((c->ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		goto cleanup;
	}

	if (SSL_CTX_set_cipher_list(c->ctx, "ECDHE-ECDSA-CHACHA20-POLY1305")
	    != 1) {
		log_warnx("%s: SSL_CTX_set_cipher", __func__);
		goto cleanup;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("%s: EC_KEY_new_by_curve", __func__);
		goto cleanup;
	}

	SSL_CTX_set_cert_store(c->ctx, passport->cacert_store);

	if ((SSL_CTX_use_certificate(c->ctx, passport->certificate)) != 1) {
		log_warnx("%s: SSL_CTX_use_certificate", __func__);
		goto cleanup;
	}

	if ((SSL_CTX_use_PrivateKey(c->ctx, passport->keyring)) != 1) {
		log_warnx("%s: SSL_CTX_use_PrivateKey", __func__);
		goto cleanup;
	}

	if ((c->ssl = SSL_new(c->ctx)) == NULL) {
		log_warnx("%s: SSL_new", __func__);
		goto cleanup;
	}

	SSL_set_tlsext_host_name(c->ssl, passport->nodeinfo->networkid);

	if ((c->bev = bufferevent_openssl_socket_new(ev_base, fd, c->ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		log_warnx("%s: bufferevent_openssl_socket_new", __func__);
		goto cleanup;
	}

	bufferevent_enable(c->bev, EV_READ | EV_WRITE);
	bufferevent_setcb(c->bev, client_onread_cb, NULL, client_onevent_cb,
	    NULL);

	if (bufferevent_socket_connect(c->bev, res->ai_addr, res->ai_addrlen)
	    < 0) {
		log_warnx("%s: bufferevent_socket_connected", __func__);
		goto cleanup;
	}

	EC_KEY_free(ecdh);
	freeaddrinfo(res);
	return (c);

cleanup:
	EC_KEY_free(ecdh);
	tls_client_free(c);
	freeaddrinfo(res);
	close(fd);
	return (NULL);
}

void
tls_client_free(struct tls_client *c)
{
	SSL_free(c->ssl);
	SSL_CTX_free(c->ctx);
	if (c->bev != NULL)
		bufferevent_free(c->bev);
	free(c);
}

int
control_init(const char *network_name)
{
	struct tls_client	*c;
	passport_t		*passport;
	const char		*pvkey;
	const char		*cert;
	const char		*cacert;

	// XXX init globally
	log_init(2, LOG_DAEMON);

	printf("network name: %s\n", network_name);

	if (ndb_network(network_name, &pvkey, &cert, &cacert) < 0) {
		log_warnx("%s: the network doesn't exist: %s\n",
		    __func__, network_name);
		goto error;
	}

	if ((passport = pki_passport_load_from_memory(cert, pvkey, cacert))
	    == NULL) {
		log_warnx("%s: pki_passport_load_from_memory", __func__);
		goto error;
	}

	if ((c = tls_client_new("127.0.0.1", "7032", passport)) == NULL) {
		log_warnx("%s: tls_client_new", __func__);
		goto error;
	}

	return (0);

error:

	return (-1);
}

void
control_fini(void)
{
	// XXX free everything
}
