/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
 * Nicolas J. Bouliane <admin@netvirt.org>
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

#include <errno.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <jansson.h>

#include <logger.h>
#include "ctrler2.h"
#include "dao.h"
#include "pki.h"
#include "request.h"

static struct ctrler_cfg *cfg = NULL;

static void
sinfo_free(struct session_info *sinfo)
{
	free(sinfo);
}

static struct session_info *
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

static void
dispatch_operation(struct session_info *sinfo, json_t *jmsg)
{
	char	*dump;
	char	*action;

	dump = json_dumps(jmsg, 0);
	printf("dump: %s\n", dump);
	free(dump);
	
	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1) {
		/* XXX disconnect */
		return;
	}

	if (strcmp(action, "add-account") == 0) {
		addAccount(sinfo, jmsg);
	} else if (strcmp(action, "activate-account") == 0) {
		activateAccount(sinfo, jmsg);
	} else if (strcmp(action, "get-account-apikey") == 0) {
		getAccountApiKey(sinfo, jmsg);
	} else if (strcmp(action, "add-network") == 0) {
		addNetwork(sinfo, jmsg);
	} else if (strcmp(action, "del-network") == 0) {
		delNetwork(sinfo, jmsg);
	} else if (strcmp(action, "list-network") == 0) {
		listNetwork(sinfo, jmsg);
	} else if (strcmp(action, "add-node") == 0) {
		addNode(sinfo, jmsg);
	} else if (strcmp(action, "del-node") == 0) {
		delNode(sinfo, jmsg);
	} else if (strcmp(action, "list-node") == 0) {
		listNode(sinfo, jmsg);
	}
}

static void
on_read_cb(struct bufferevent *bev, void *session)
{
	char			 buf[1024];
	int			 n;
	json_error_t		 error;
	json_t			*jmsg = NULL;
	struct session_info	*sinfo;

	jlog(L_NOTICE, "on_read_cb");
	sinfo = (struct session_info*)session;

	while ((n = bufferevent_read(bev, buf, sizeof(buf))) > 0) {
		jmsg = json_loadb(buf, n, 0, &error);
		if (jmsg == NULL) {
			printf("error: %s\n", error.text);
		} else {
			dispatch_operation(sinfo, jmsg);
			json_decref(jmsg);
		}
	}
}

static void
on_event_cb(struct bufferevent *bev, short events, void *ptr)
{
	printf("events: %x\n", events);
	struct session_info	*sinfo = ptr;
	if (events & BEV_EVENT_ERROR) {
		jlog(L_ERROR, "error from bufferevent");
	} else if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		jlog(L_NOTICE, "disconnected");
		bufferevent_free(bev);
		sinfo_free(sinfo);
	}
}

static void
on_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	struct bufferevent *bev = (struct bufferevent *)arg;
	printf("timeout!\n");
	bufferevent_free(bev);
}

static void
accept_conn_cb(struct evconnlistener *listener,
	evutil_socket_t fd, struct sockaddr *address, int socklen,
	void *arg)
{
	struct timeval		 tv = {1, 0};
	struct event_base	*base;
	struct bufferevent	*bev;
	struct session_info	*sinfo;
	struct event		*ev;
	SSL_CTX			*server_ctx;
	SSL			*client_ctx;

	server_ctx = (SSL_CTX *)arg;
	client_ctx = SSL_new(server_ctx);
	base = evconnlistener_get_base(listener);

	if ((bev = bufferevent_openssl_socket_new(base, fd, client_ctx,
					BUFFEREVENT_SSL_ACCEPTING,
					BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		jlog(L_ERROR, "bufferevent_openssl_socket_new failed");
		return;
	}

	jlog(L_NOTICE, "new connection");

	sinfo = sinfo_new();
	sinfo->bev = bev;

	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_setcb(bev, on_read_cb, NULL, on_event_cb, sinfo);

	/* Disconnect stalled session */
	ev = event_new(base, -1, EV_TIMEOUT, on_timeout_cb, bev);
	event_add(ev, &tv);
}

static void
accept_error_cb(struct evconnlistener *listener, void *ptr)
{
	struct event_base	*base;
	int			 err;

	base = evconnlistener_get_base(listener);
	err = EVUTIL_SOCKET_ERROR();
	jlog(L_ERROR, "Got an error %d (%s) on the listener."
		"Shutting down.\n", err, evutil_socket_error_to_string(err));

	event_base_loopexit(base, NULL);
}

void
sighandler(evutil_socket_t sk, short t, void *ptr)
{
	struct event_base	*ev_base;

	ev_base = (struct event_base *)ptr;
	event_base_loopbreak(ev_base);
}

static DH *
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

static SSL_CTX *
evssl_init()
{
	passport_t	*passport;
	SSL_CTX		*server_ctx = NULL;

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		return NULL;

	passport = pki_passport_load_from_file(cfg->certificate, cfg->privatekey, cfg->trusted_cert);


	server_ctx = SSL_CTX_new(TLSv1_2_server_method());
	SSL_CTX_set_tmp_dh(server_ctx, get_dh_1024());

	SSL_CTX_set_cipher_list(server_ctx, "DHE-RSA-AES256-GCM-SHA384");
	SSL_CTX_set_cert_store(server_ctx, passport->cacert_store);

	SSL_CTX_use_certificate(server_ctx, passport->certificate);
	SSL_CTX_use_PrivateKey(server_ctx, passport->keyring);

	return server_ctx;
}

static struct event		*ev_int;
static struct event_base	*base;
static struct evconnlistener	*listener;

int
ctrler2_init(struct ctrler_cfg *_cfg)
{
	SSL_CTX			*ctx;
	struct sockaddr_in	 sin;

	cfg = _cfg;
	cfg->ctrler_running = 1;

	if ((ctx = evssl_init()) == NULL) {
		jlog(L_ERROR, "evssl_init failed");
		return -1;
	}

	base = event_base_new();
	if (base == NULL) {
		jlog(L_ERROR, "couldn't open event base");
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(9093);

	listener = evconnlistener_new_bind(base, accept_conn_cb, ctx,
		LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
		(struct sockaddr*)&sin, sizeof(sin));
	if (listener == NULL) {
		jlog(L_ERROR, "Couldn't create listener");
		return -1;
	}

	ev_int = evsignal_new(base, SIGINT, sighandler, base);
	event_add(ev_int, NULL);

	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(base);

	return 0;
}

void
ctrler2_fini()
{
	evsignal_del(ev_int);
	evconnlistener_free(listener);
	event_base_free(base);
}
