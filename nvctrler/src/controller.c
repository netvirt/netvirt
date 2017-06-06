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

#include <err.h>
#include <errno.h>
#include <signal.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <jansson.h>

#include <log.h>
#include <pki.h>

#include "controller.h"
#include "dao.h"
#include "request.h"

struct session_info		*switch_sinfo = NULL;

static passport_t		*passport;
static struct evconnlistener	*listener;
static SSL_CTX			*ctx;

void controller_init();
void controller_fini();

struct session_info *
sinfo_new()
{
	struct session_info *sinfo = calloc(1, sizeof(struct session_info));
	sinfo->state = SESSION_NOT_AUTH;

	return sinfo;
}
void
sinfo_free(struct session_info **sinfo)
{
	(*sinfo)->bev = NULL;
	memset((*sinfo)->cert_name, 0, sizeof((*sinfo)->cert_name));
	free(*sinfo);
	*sinfo = NULL;
}

void
on_read_cb(struct bufferevent *bev, void *arg)
{
	struct session_info	*session;
	json_t			*jmsg = NULL;
	json_error_t		 error;
	size_t			 n_read_out;
	const char		*action;
	char			*msg;

	printf("on read cb\n");

	session = arg;

	while (evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
		if ((msg = evbuffer_readln(bufferevent_get_input(bev),
				&n_read_out, EVBUFFER_EOL_LF)) == NULL)
			return;

		if ((jmsg = json_loadb(msg, n_read_out, 0, &error)) == NULL) {
			log_warnx("%s: json_loadb: %s", __func__, error.text);
			goto error;
		}

		if (json_unpack(jmsg, "{s:s}", "action", &action) < 0) {
			log_warnx("%s: json_unpack", __func__);
			goto error;
		}

		if (strcmp(action, "switch-network-list") == 0) {
			if (switch_network_list(session, jmsg) < 0) {
				log_warnx("%s: switch_network_list", __func__);
				goto error;
			}
		} else if (strcmp(action, "switch-node-list") == 0) {
			if (switch_node_list(session, jmsg) < 0) {
				log_warnx("%s: switch_node_list", __func__);
				goto error;
			}
		} else
			goto error;

		json_decref(jmsg);
		free(msg);
	}

	return;

error:
	json_decref(jmsg);
	free(msg);
	/* Disconnect */
	bufferevent_free(bev);
}

void
on_connect_cb(struct bufferevent *bev, void *arg)
{
	struct session_info	*session;
	SSL			*client_ssl;
	X509			*cert;
	X509_NAME		*subj_ptr;

	session = arg;

	client_ssl = bufferevent_openssl_get_ssl(bev);
	if ((cert = SSL_get_peer_certificate(client_ssl)) == NULL)
		return;

	subj_ptr = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subj_ptr, NID_commonName,
		session->cert_name, sizeof(session->cert_name));
	X509_free(cert);

	if (strncmp("netvirt-switch", session->cert_name, 14)== 0) {
		session->type = NVSWITCH;
		switch_sinfo = session;
	}

	log_info("%s: cert: %s", __func__, session->cert_name);
}

void
on_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct session_info	*session;
	unsigned long		 e;

	printf("on event cb\n");

	session = arg;
	e = 0;

	if (events & BEV_EVENT_CONNECTED) {
		on_connect_cb(bev, arg);
	} else if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		log_warnx("%s: event (%x)", __func__, events);
		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			log_warnx("%s: %s", __func__,
			    ERR_error_string(e, NULL));
		}

		switch_sinfo = NULL;
		log_warnx("%s: switch disconnected", __func__);
		dao_reset_node_state();
		sinfo_free(&session);
		bufferevent_free(bev);
	}
}

void
on_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	bufferevent_free(arg);
}

void
accept_conn_cb(struct evconnlistener *listener,
	evutil_socket_t fd, struct sockaddr *address, int socklen,
	void *arg)
{
	struct event_base	*base;
	struct bufferevent	*bev;
	struct session_info	*sinfo;
	SSL			*client_ssl;

	client_ssl = SSL_new(ctx);
	base = evconnlistener_get_base(listener);

	if ((bev = bufferevent_openssl_socket_new(base, fd, client_ssl,
					BUFFEREVENT_SSL_ACCEPTING,
					BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		log_warnx("%s: bufferevent_openssl_socket_new", __func__);
		/* XXX */
	}

	warnx("new connection");

	sinfo = sinfo_new();
	sinfo->bev = bev;

	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_setcb(bev, on_read_cb, NULL, on_event_cb, sinfo);
}

void
accept_error_cb(struct evconnlistener *listener, void *ptr)
{

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

SSL_CTX *
evssl_init()
{
	DH	*dh = NULL;
	EC_KEY	*ecdh = NULL;
	SSL_CTX	*ctx = NULL;
	int	 ret;

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		goto error;

	ret = -1;
	if ((ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL) {
		log_warn("SSL_CTX_new");
		goto error;
	}

	if ((dh = get_dh_1024()) == NULL) {
		log_warn("get_dh_1024");
		goto error;
	}

	if ((SSL_CTX_set_tmp_dh(ctx, dh)) != 1) {
		log_warn("SSL_CTX_set_tmp");
		goto error;
	}

	if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-CHACHA20-POLY1305") != 1) {
		log_warn("SSL_CTX_set_cipher");
		goto error;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warn("EC_KEY_new_by_curve_name");
		goto error;
	}

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) {
		log_warn("SSL_CTX_set_tmp_ecdh");
		goto error;
	}

	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	if (SSL_CTX_use_certificate(ctx, passport->certificate) != 1) {
		log_warn("SSL_CTX_use_certificate");
		goto error;
	}

	if (SSL_CTX_use_PrivateKey(ctx, passport->keyring) != 1) {
		log_warn("SSL_CTX_use_PrivateKey");
		goto error;
	}

	SSL_CTX_set_verify(ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	ret = 0;

error:
	if (ret < 0) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
	DH_free(dh);
	EC_KEY_free(ecdh);
	return (ctx);
}

void
controller_init()
{
	struct addrinfo		*res;
	struct addrinfo		 hints;
	const char		*cert;
	const char		*pvkey;
	const char		*cacert;

	dao_reset_node_state();

	if (json_unpack(config, "{s:s}", "cert", &cert) < 0)
		fatalx("'cert' not found in config");

	if (json_unpack(config, "{s:s}", "pvkey", &pvkey) < 0)
		fatalx("'pvkey' not found in config");

	if (json_unpack(config, "{s:s}", "cacert", &cacert) < 0)
		fatalx("'cacert' not found in config");

	if ((passport = pki_passport_load_from_file(cert, pvkey, cacert))
	    == NULL)
		fatalx("can't load passport from: \n\t%s\n\t%s\n\t%s\n",
		    cert, pvkey, cacert);

	if ((ctx = evssl_init()) == NULL)
		fatalx("evssl_init");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo("0.0.0.0", "9093", &hints, &res);

	if ((listener = evconnlistener_new_bind(ev_base, accept_conn_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
	    res->ai_addr, res->ai_addrlen)) == NULL)
		errx(1, "evconnlistener_new_bind failed");

	evconnlistener_set_error_cb(listener, accept_error_cb);
}

void
controller_fini()
{
	pki_passport_free(passport);
	SSL_CTX_free(ctx);
	dao_reset_node_state();
	if  (listener != NULL)
		evconnlistener_free(listener);
}
