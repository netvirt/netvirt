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

#include <dnds.h>
#include <logger.h>

#include "context.h"
#include "dsc.h"
#include "request.h"
#include "session.h"

void provRequest(struct session *session, DNDSMessage_t *req_msg)
{
	jlog(L_DEBUG, "PROV REQUEST !\n");

	size_t length;
	char *provcode = NULL;

	ProvRequest_get_provCode(req_msg, &provcode, &length);
	jlog(L_DEBUG, "prov code: %s\n", provcode);

	transmit_provisioning(session, provcode, length);
}

int authRequest(struct session *session, DNDSMessage_t *req_msg)
{
	char *certName;
	size_t length;
	uint32_t context_id;

	AuthRequest_printf(req_msg);
	AuthRequest_get_certName(req_msg, &certName, &length);

	if (session->state != SESSION_STATE_NOT_AUTHED) {
		jlog(L_NOTICE, "dnd]> authRequest duplicate");
		return -1;
	}

	DNDSMessage_t *msg = NULL;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_authResponse);

	AuthRequest_get_certName(req_msg, &certName, &length);

	/* something@id */
	printf("certName: %s\n", certName);
	context_id = atoi(strchr(certName,'@')+1); //XXX atoi(NULL) doesn't like it
	printf("contextid %i\n", context_id);
	session->context = context_lookup(context_id);

	if (session->context != NULL) {

		session->cert_name = strdup(certName);
		if (session->netc->security_level == NET_UNSECURE) {

			AuthResponse_set_result(msg, DNDSResult_success);
			net_send_msg(session->netc, msg);

			session->state = SESSION_STATE_AUTHED;
			session->netc->on_secure(session->netc);

		} else {

			AuthResponse_set_result(msg, DNDSResult_secureStepUp);
			net_send_msg(session->netc, msg);

			krypt_add_passport(session->netc->kconn, session->context->passport);
			session->state = SESSION_STATE_WAIT_STEPUP;
			net_step_up(session->netc);
		}
	} else {

		AuthResponse_set_result(msg, DNDSResult_insufficientAccessRights);
		net_send_msg(session->netc, msg);
		DNDSMessage_del(msg);

		return -1;
	}

	DNDSMessage_del(msg);

	return 0;
}

void p2pRequest(struct session *session_a, struct session *session_b)
{
	DNDSMessage_t *msg;

	uint32_t port;
	char *ip_a;
	char *ip_b;

	if (session_a->netc == NULL || session_b->netc == NULL) {
		return;
	}

	if (!strcmp(session_a->netc->peer->host, session_b->netc->peer->host)) {
		ip_a = strdup(session_a->ip_local);
		ip_b = strdup(session_b->ip_local);
	} else {
		ip_a = strdup(session_a->netc->peer->host);
		ip_b = strdup(session_b->netc->peer->host);
	}

	 /* basic random port : 49152–65535 */
	port = rand() % (65535-49152+1)+49152;

	jlog(L_DEBUG, "A ip public %s\n", ip_a);
	jlog(L_DEBUG, "B ip public %s\n", ip_b);

	/* msg session A */
	DNDSMessage_new(&msg);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_operation(msg, dnop_PR_p2pRequest);

	P2pRequest_set_macAddrDst(msg, session_b->tun_mac_addr);
	P2pRequest_set_ipAddrDst(msg, ip_b);
	P2pRequest_set_port(msg, port);
	P2pRequest_set_side(msg, P2pSide_client);

	net_send_msg(session_a->netc, msg);
	DNDSMessage_del(msg);

	/* msg session B */
	DNDSMessage_new(&msg);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_operation(msg, dnop_PR_p2pRequest);

	P2pRequest_set_macAddrDst(msg, session_a->tun_mac_addr);
	P2pRequest_set_ipAddrDst(msg, ip_a);
	P2pRequest_set_port(msg, port);
	P2pRequest_set_side(msg, P2pSide_server);

	net_send_msg(session_b->netc, msg);
	DNDSMessage_del(msg);
}
