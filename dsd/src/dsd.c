/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds.h>
#include <event.h>
#include <journal.h>
#include <net.h>
#include <pki.h>

#include "dao.h"
#include "dsd.h"
#include "request.h"

static void session_free(struct session *session)
{
	free(session);
}

static struct session *session_new()
{
	struct session *session = calloc(1, sizeof(struct session));
	session->status = SESSION_STATUS_NOT_AUTHED;

	return session;
}

static void terminate(struct session *session)
{
	net_disconnect(session->netc);
	session_free(session);
}

static int validate_msg(DNDSMessage_t *msg)
{
	pdu_PR pdu;
	DNDSMessage_get_pdu(msg, &pdu);

	if (pdu != pdu_PR_dsm) {
		jlog(L_NOTICE, "dsd]> not a valid DSM data unit");
		return -1;
	}

	return 0;
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
			addRequest(session, msg);
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
			jlog(L_NOTICE, "dsd]> not a valid DSM operation");
		case dsop_PR_terminateRequest:
			terminate(session);
			break;
	}
}

static void on_secure(netc_t *netc)
{
	jlog(L_DEBUG, "on secure!\n");
}

static void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	struct session *session;
	mbuf_t **mbuf_itr;

	mbuf_itr = &netc->queue_msg;
	session = (struct session *)netc->ext_ptr;

	while (*mbuf_itr != NULL) {

		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;
		DNDSMessage_printf(msg);

		if (validate_msg(msg) == 0)
			dispatch_operation(session, msg);
		else {
			terminate(session);
			return;
		}

		mbuf_del(mbuf_itr, *mbuf_itr);
	}

	return;
}

static void on_disconnect(netc_t *netc)
{
	struct session *session;
	session = (struct session *)netc->ext_ptr;

	session_free(session);
}

/* TODO having a timeout per session */
static void timeout_session(struct session *session)
{
	terminate(session);
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

void dsd_fini(void *ext_ptr)
{

}

int dsd_init(char *ip_address, char *port, char *certificate, char *privatekey, char *trusted_authority)
{
	int ret;

	event_register(EVENT_EXIT, "dsd_fini", dsd_fini, PRIO_AGNOSTIC);

	passport_t *dsd_passport;
	dsd_passport = pki_passport_load_from_file(certificate, privatekey, trusted_authority);

	ret = net_server(ip_address, port, NET_PROTO_TCP, NET_SECURE_RSA, dsd_passport,
			on_connect, on_disconnect, on_input, on_secure);

	if (ret < 0) {
		jlog(L_NOTICE, "dsd]> net_server failed :: %s:%i\n", __FILE__, __LINE__);
		return -1;
	}

	return 0;
}
