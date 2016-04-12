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

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <jansson.h>

#include <logger.h>
#include "ctrler.h"
#include "dao.h"
#include "pki.h"
#include "request.h"

struct session_info *switch_sinfo = NULL;
static struct ctrler_cfg *cfg = NULL;

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
	jlog(L_DEBUG, "jmsg: %s", dump);
	free(dump);

	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1) {
		/* XXX disconnect */
		return;
	}

	if (strcmp(action, "listall-network") == 0) {
		listall_network(sinfo, jmsg);
	} else if (strcmp(action, "listall-node") == 0) {
		listall_node(sinfo, jmsg);
	} else if (strcmp(action, "provisioning") == 0) {
		provisioning(sinfo, jmsg);
	} else if (strcmp(action, "update-node-status") == 0) {
		update_node_status(sinfo, jmsg);
	}
}

void
dispatch_nvapi(struct session_info *sinfo, json_t *jmsg)
{
	char	*dump;
	char	*action;

	dump = json_dumps(jmsg, 0);
	jlog(L_DEBUG, "jmsg: %s", dump);
	free(dump);

	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1) {
		/* XXX disconnect */
		return;
	}

	if (strcmp(action, "add-account") == 0) {
		add_account(sinfo, jmsg);
	} else if (strcmp(action, "activate-account") == 0) {
		activate_account(sinfo, jmsg);
	} else if (strcmp(action, "get-account-apikey") == 0) {
		get_account_apikey(sinfo, jmsg);
	} else if (strcmp(action, "add-network") == 0) {
		add_network(sinfo, jmsg);
	} else if (strcmp(action, "del-network") == 0) {
		del_network(sinfo, jmsg);
	} else if (strcmp(action, "list-network") == 0) {
		list_network(sinfo, jmsg);
	} else if (strcmp(action, "add-node") == 0) {
		add_node(sinfo, jmsg);
	} else if (strcmp(action, "del-node") == 0) {
		del_node(sinfo, jmsg);
	} else if (strcmp(action, "list-node") == 0) {
		list_node(sinfo, jmsg);
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

	//jlog(L_DEBUG, "on_read_cb");
	sinfo = session;

	str = evbuffer_readln(bufferevent_get_input(bev),
			&n_read_out,
			EVBUFFER_EOL_LF);

	if (str == NULL)
		return;

	jmsg = json_loadb(str, n_read_out, 0, &error);
	if (jmsg == NULL) {
		jlog(L_ERROR, "json_loadb: %s", error.text);
		/* FIXME DISCONNECT */
		return;
	}

	if (sinfo->type == NVSWITCH)
		dispatch_nvswitch(&sinfo, jmsg);
	else if (sinfo->type == NVAPI)
		dispatch_nvapi(sinfo, jmsg);
	else {
		bufferevent_free(bev);
		sinfo_free(&sinfo);
	}
	json_decref(jmsg);
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
	} else {
		sinfo->type = NVAPI;
	}
	jlog(L_DEBUG, "cert: %s", sinfo->cert_name);
}

void
on_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct session_info	*sinfo = arg;
	unsigned long e = 0;

	if (events & BEV_EVENT_CONNECTED) {
		on_connect_cb(bev, arg);
	} else if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		jlog(L_DEBUG, "event (%x)", events);

		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			jlog(L_ERROR, "%s", ERR_error_string(e, NULL));
		}

		if (sinfo->type == NVSWITCH) {
			switch_sinfo = NULL;
			jlog(L_DEBUG, "switch disconnected");
		}
		sinfo_free(&sinfo);
		//bufferevent_free(bev);
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
	SSL_CTX			*server_ctx;
	SSL			*client_ssl;

	server_ctx = (SSL_CTX *)arg;
	client_ssl = SSL_new(server_ctx);
	base = evconnlistener_get_base(listener);

	if ((bev = bufferevent_openssl_socket_new(base, fd, client_ssl,
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
//	ev = event_new(base, -1, EV_TIMEOUT, on_timeout_cb, bev);
//	event_add(ev, &tv);

}

void
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
	passport_t	*passport;
	SSL_CTX		*server_ctx = NULL;

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		return NULL;

	passport = pki_passport_load_from_file(cfg->certificate, cfg->privatekey, cfg->trusted_cert);

	server_ctx = SSL_CTX_new(TLSv1_2_server_method());
	SSL_CTX_set_tmp_dh(server_ctx, get_dh_1024());

	SSL_CTX_set_cipher_list(server_ctx, "AES256-GCM-SHA384");
	//SSL_CTX_set_cipher_list(server_ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");

	SSL_CTX_set_cert_store(server_ctx, passport->cacert_store);
	SSL_CTX_use_certificate(server_ctx, passport->certificate);
	SSL_CTX_use_PrivateKey(server_ctx, passport->keyring);

	SSL_CTX_set_verify(server_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	return server_ctx;
}

static struct event		*ev_int = NULL;
static struct event_base	*base = NULL;
static struct evconnlistener	*listener = NULL;

int
ctrler_init(struct ctrler_cfg *_cfg)
{
	SSL_CTX			*ctx;
	struct sockaddr_in	 sin;

	cfg = _cfg;
	cfg->ctrler_running = 1;

	if ((ctx = evssl_init()) == NULL) {
		jlog(L_ERROR, "evssl_init failed");
		return -1;
	}

	if ((base = event_base_new()) == NULL) {
		jlog(L_ERROR, "event_base_new failed");
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
		jlog(L_ERROR, "couldn't create listener");
		return -1;
	}

	ev_int = evsignal_new(base, SIGINT, sighandler, base);
	event_add(ev_int, NULL);

	signal(SIGPIPE, SIG_IGN);

	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(base);

	return 0;
}

void
ctrler_fini()
{
	if (ev_int != NULL)
		evsignal_del(ev_int);
	if (listener != NULL)
		evconnlistener_free(listener);
	event_base_free(base);
}
