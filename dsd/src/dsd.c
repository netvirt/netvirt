/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
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

#include <pthread.h>

#include <dnds.h>
#include <logger.h>
#include <netbus.h>

#include "dao.h"
#include "dsd.h"
#include "pki.h"
#include "request.h"
#include "tcp.h"

passport_t *g_dsd_passport;

static void session_free(struct session *session)
{
	free(session);
}

static struct session *session_new()
{
	struct session *session = calloc(1, sizeof(struct session));
	session->state = SESSION_STATE_NOT_AUTHED;

	return session;
}

static void terminate(struct session *session)
{
	net_disconnect(session->netc);
	session_free(session);
}

static void dispatch_operation(struct session *session, DNDSMessage_t *msg)
{
	dsop_PR operation;
	DSMessage_get_operation(msg, &operation);

	switch (operation) {
	case dsop_PR_nodeConnectInfo:
		nodeConnectInfo(session, msg);
		break;

	case dsop_PR_addRequest:
		addRequest(msg);
		break;

	case dsop_PR_delRequest:
		delRequest(session, msg);
		break;

	case dsop_PR_modifyRequest:
		modifyRequest(session, msg);
		break;

	case dsop_PR_searchRequest:
		searchRequest(session, msg);
		break;

	/* terminateRequest is a special case since
	 * it has no Response message associated with it.
	 * simply disconnect the client;
	 */
	case dsop_PR_NOTHING:
	default:
		jlog(L_WARNING, "dsd]> not a valid DSM operation");
	case dsop_PR_terminateRequest:
		terminate(session);
		break;
	}
}

static void on_secure(netc_t *netc)
{
	jlog(L_DEBUG, "dsd]> connection secured");
	if (!strncmp("dnd", netc->kconn->client_cn, 3)) {
		jlog(L_NOTICE, "dsd]> %s authenticated", netc->kconn->client_cn);
		g_dnd_netc = netc;
	}
}

static void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	struct session *session;
	mbuf_t **mbuf_itr;
	pdu_PR pdu;

	mbuf_itr = &netc->queue_msg;
	session = netc->ext_ptr;

	while (*mbuf_itr != NULL) {
		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;
		DNDSMessage_get_pdu(msg, &pdu);

		switch (pdu) {
		case pdu_PR_dsm:
			dispatch_operation(session, msg);
			break;
		default:
			terminate(session);
			return;
		}
		mbuf_del(mbuf_itr, *mbuf_itr);
	}
}

static void on_disconnect(netc_t *netc)
{
	struct session *session;
	session = netc->ext_ptr;

	session_free(session);
}

static void on_connect(netc_t *netc)
{
	struct session *session;
	session = session_new();

	if (session == NULL) {
		net_disconnect(netc);
		return;
	}

	session->netc = netc;
	netc->ext_ptr = session;
}

static void *dsd_loop(void *nil)
{
	(void)(nil); /* unused */

	while (1) {
		tcpbus_ion_poke();
	}

	return NULL;
}

int dsd_init(struct dsd_cfg *dsd_cfg)
{
	int ret;

	g_dsd_passport = pki_passport_load_from_file(dsd_cfg->certificate, dsd_cfg->privatekey, dsd_cfg->trusted_cert);

	ret = net_server(dsd_cfg->ipaddr, dsd_cfg->port, NET_PROTO_TCP, NET_SECURE_RSA, g_dsd_passport,
			on_connect, on_disconnect, on_input, on_secure);

	if (ret < 0) {
		jlog(L_NOTICE, "dsd]> net_server failed");
		return -1;
	}

	pthread_t thread_loop;
	pthread_create(&thread_loop, NULL, dsd_loop, NULL);

	return 0;
}
