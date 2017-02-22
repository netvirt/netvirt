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

extern json_t			*config;
extern struct event_base	*ev_base;
struct session_info		*switch_sinfo = NULL;

static passport_t		*passport;
static struct evconnlistener	*listener;
static SSL_CTX			*ctx;

void controller_init();
void controller_fini();

void
sinfo_free(struct session_info **sinfo)
{
	(*sinfo)->bev = NULL;
	memset((*sinfo)->cert_name, 0, sizeof((*sinfo)->cert_name));
	free(*sinfo);
	*sinfo = NULL;
}

struct session_info *
sinfo_new()
{
	struct session_info *sinfo = calloc(1, sizeof(struct session_info));
	sinfo->state = SESSION_NOT_AUTH;

	return sinfo;
}

char *
response()
{
	char	*ret_strings = NULL;
	json_t	*root = json_object();

	json_object_set_new(root, "reponse", json_string("malformed"));
	json_object_set_new(root, "action", json_string("response"));

	ret_strings = json_dumps(root, 0);
	json_decref(root);

	return ret_strings;
}

void
dispatch_nvswitch(struct session_info **sinfo, json_t *jmsg)
{
	char	*dump;
	char 	*action;

	dump = json_dumps(jmsg, 0);
	warnx("jmsg: %s", dump);
	free(dump);

	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1) {
		/* XXX disconnect */
		return;
	}

	if (strcmp(action, "network-listall") == 0) {
		listall_network(sinfo, jmsg);
	} else if (strcmp(action, "node-listall") == 0) {
		listall_node(sinfo, jmsg);
	} else if (strcmp(action, "node-update-status") == 0) {
		update_node_status(sinfo, jmsg);
	}
}

void
on_read_cb(struct bufferevent *bev, void *session)
{
	char			*str;
	size_t			 n_read_out;
	json_error_t		 error;
	json_t			*jmsg = NULL;
	struct session_info	*sinfo;

	printf("on read cb\n");

	sinfo = session;

	str = evbuffer_readln(bufferevent_get_input(bev),
			&n_read_out,
			EVBUFFER_EOL_LF);

	if (str == NULL)
		return;

	if ((jmsg = json_loadb(str, n_read_out, 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		/* FIXME DISCONNECT */
		goto out;
	}

	if (sinfo->type == NVSWITCH)
		dispatch_nvswitch(&sinfo, jmsg);
	else {
		bufferevent_free(bev);
		sinfo_free(&sinfo);
	}
	json_decref(jmsg);
out:
	free(str);
}

void
on_connect_cb(struct bufferevent *bev, void *arg)
{
	SSL			*client_ssl;
	X509			*cert;
	X509_NAME		*subj_ptr;
	struct session_info	*sinfo = arg;

	client_ssl = bufferevent_openssl_get_ssl(bev);
	cert = SSL_get_peer_certificate(client_ssl);
	if (cert == NULL)
		return;

	subj_ptr = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subj_ptr, NID_commonName,
		sinfo->cert_name, sizeof(sinfo->cert_name));
	X509_free(cert);

	if (strncmp("netvirt-switch", sinfo->cert_name, strlen("netvirt-switch")) == 0) {
		sinfo->type = NVSWITCH;
		switch_sinfo = sinfo;
	}
	warnx("cert: %s", sinfo->cert_name);
}

void
on_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct session_info	*sinfo = arg;
	unsigned long e = 0;

	printf("on event cb\n");
	if (events & BEV_EVENT_CONNECTED) {
		on_connect_cb(bev, arg);
	} else if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		warnx("event (%x)", events);

		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			warnx("%s", ERR_error_string(e, NULL));
		}

		if (sinfo->type == NVSWITCH) {
			switch_sinfo = NULL;
			warnx("switch disconnected");
			dao_reset_node_state();
		}
		sinfo_free(&sinfo);
		bufferevent_free(bev);
	}
}

void
on_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	struct bufferevent *bev = (struct bufferevent *)arg;
	printf("timeout!\n");
	bufferevent_free(bev);
}

void
accept_conn_cb(struct evconnlistener *listener,
	evutil_socket_t fd, struct sockaddr *address, int socklen,
	void *arg)
{
//	struct timeval		 tv = {1, 0};
	struct event_base	*base;
	struct bufferevent	*bev;
	struct session_info	*sinfo;
//	struct event		*ev;
	SSL			*client_ssl;

	client_ssl = SSL_new(ctx);
	base = evconnlistener_get_base(listener);

	if ((bev = bufferevent_openssl_socket_new(base, fd, client_ssl,
					BUFFEREVENT_SSL_ACCEPTING,
					BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		warnx("bufferevent_openssl_socket_new failed");
		return;
	}

	warnx("new connection");

	sinfo = sinfo_new();
	sinfo->bev = bev;

	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_setcb(bev, on_read_cb, NULL, on_event_cb, sinfo);

	/* Disconnect stalled session */
//	ev = event_new(base, -1, EV_TIMEOUT, on_timeout_cb, bev);
//	event_add(ev, &tv);

}

void
accept_error_cb(struct evconnlistener *listener, void *ptr)
{
	struct event_base	*base;

	base = evconnlistener_get_base(listener);
/*
	err = EVUTIL_SOCKET_ERROR();
	warnx("error %d (%s) on the listener."
		"Shutting down.\n", err, evutil_socket_error_to_string(err));
*/

	event_base_loopexit(base, NULL);
}

void
sighandler(evutil_socket_t sk, short t, void *ptr)
{
	struct event_base	*ev_base;

	ev_base = (struct event_base *)ptr;
	event_base_loopbreak(ev_base);
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
		return NULL;
	}

	dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
	dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

	if (dh->p == NULL || dh->g == NULL) {
		DH_free(dh);
		return NULL;
	}

	return dh;
}

SSL_CTX *
evssl_init()
{
	DH	*dh = NULL;
	EC_KEY	*ecdh = NULL;
	SSL_CTX	*ctx = NULL;

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		goto error;

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

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	DH_free(dh);
	EC_KEY_free(ecdh);
	return ctx;

error:
	DH_free(dh);
	EC_KEY_free(ecdh);
	SSL_CTX_free(ctx);
	return NULL;


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
		fatalx("certificate not found in config");

	if (json_unpack(config, "{s:s}", "pvkey", &pvkey) < 0)
		fatalx("privatekey not found in config");

	if (json_unpack(config, "{s:s}", "cacert", &cacert) < 0)
		fatalx("trusted_cert not found in config");

	if ((passport = pki_passport_load_from_file(cert, pvkey, cacert)) == NULL)
		fatalx("can't load passport from: \n\t%s\n\t%s\n\t%s\n", cert, pvkey, cacert);

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
