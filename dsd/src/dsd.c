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

#include <dnds/dnds.h>
#include <dnds/event.h>
#include <dnds/journal.h>
#include <dnds/net.h>
#include <dnds/pki.h>

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
		JOURNAL_NOTICE("dsd]> not a valid DSM data unit");
		return -1;
	}

	return 0;
}

static void dispatch_operation(struct session *session, DNDSMessage_t *msg)
{
	dsop_PR operation;
	DSMessage_get_operation(msg, &operation);

	printf("operation %i\n", operation);
	printf("peerConnectInfo %i\n", dsop_PR_peerConnectInfo);
	printf("authRequest %i\n", dsop_PR_authRequest);
	switch (operation) {

		case dsop_PR_peerConnectInfo:
			peerConnectInfo(session, msg);
			break;

		case dsop_PR_authRequest:
			authRequest(session, msg);
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
			JOURNAL_NOTICE("dsd]> not a valid DSM operation");
		case dsop_PR_terminateRequest:
			terminate(session);
			break;
	}
}

static void on_secure(netc_t *netc)
{
	printf("on secure!\n");

	char *id;
	char *topology_id;
	char *description;
	char *network;
	char *netmask;
	char *serverCert;
	char *serverPrivkey;
	char *trustedCert;

	dao_fetch_context(&id,
			&topology_id,
			&description,
			&network,
			&netmask,
			&serverCert,
			&serverPrivkey,
			&trustedCert);


	DNDSMessage_t *msg;
	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 1);
	DSMessage_set_operation(msg, dsop_PR_contextInfo);

        ContextInfo_set_id(msg, atoi(id));
        ContextInfo_set_topology(msg, Topology_mesh);
        ContextInfo_set_description(msg, description, strlen(description));
        ContextInfo_set_network(msg, network);
        ContextInfo_set_netmask(msg, netmask);
        ContextInfo_set_serverCert(msg, serverCert, strlen(serverCert));
        ContextInfo_set_serverPrivkey(msg, serverPrivkey, strlen(serverPrivkey));
        ContextInfo_set_trustedCert(msg, trustedCert, strlen(trustedCert));

	net_send_msg(netc, msg);
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

static void timeout_session(struct session *session)
{
	printf("time out sess\n");
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

	ret = net_server(ip_address, port, NET_PROTO_UDT, NET_SECURE_RSA, dsd_passport,
			on_connect, on_disconnect, on_input, on_secure);

	if (ret < 0) {
		JOURNAL_NOTICE("dsd]> net_server failed :: %s:%i\n", __FILE__, __LINE__);
		return -1;
	}

	return 0;
}
