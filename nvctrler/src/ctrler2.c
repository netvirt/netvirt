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

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <jansson.h>

#include <logger.h>

#include "ctrler2.h"
#include "dao.h"
#include "pki.h"
#include "request.h"

static struct ctrler_cfg *ctrler_cfg = NULL;

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
	char	*action;
	
	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1) {
		/* XXX disconnect */
		return;
	}

	if (strcmp(action, "add-account") == 0) {
		addAccount(sinfo, jmsg);
	} else if (strcmp(action, "get-account-apikey") == 0) {
		getAccountApiKey(sinfo, jmsg);
	} else if (strcmp(action, "add-network") == 0) {
		addNetwork(sinfo, jmsg);
	} else if (strcmp(action, "list-network") == 0) {
		listNetwork(sinfo, jmsg);
	} else if (strcmp(action, "add-node") == 0) {
		addNode(sinfo, jmsg);
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
	struct session_info	*sinfo = ptr;

	if (events & BEV_EVENT_ERROR) {
		jlog(L_ERROR, "error from bufferevent\n");
	}
	if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		jlog(L_NOTICE, "disconnected\n");
		bufferevent_free(bev);
		sinfo_free(sinfo);
	}
}

static void
accept_conn_cb(struct evconnlistener *listener,
	evutil_socket_t fd, struct sockaddr *address, int socklen,
	void *ptr)
{
	struct event_base	*base;
	struct bufferevent	*bev;
	struct session_info	*sinfo;

	base = evconnlistener_get_base(listener);
	bev = bufferevent_socket_new(
		base, fd, BEV_OPT_CLOSE_ON_FREE);

	sinfo = sinfo_new();
	sinfo->bev = bev;

	bufferevent_setcb(bev, on_read_cb, NULL, on_event_cb, sinfo);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
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

	static struct event		*ev_int;
	static struct event_base	*base;
	static struct evconnlistener	*listener;

int
ctrler2_init(struct ctrler_cfg *cfg)
{
	ctrler_cfg = cfg;
	ctrler_cfg->ctrler_running = 1;

	struct sockaddr_in	 sin;

	base = event_base_new();
	if (base == NULL) {
		jlog(L_ERROR, "couldn't open event base");
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(9093);

	listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
		LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
		(struct sockaddr*)&sin, sizeof(sin));
	if (listener == NULL) {
		jlog(L_ERROR, "Coundn't create listener");
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
