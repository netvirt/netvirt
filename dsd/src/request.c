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

#include "dao.h"
#include "request.h"

void peerConnectInfo(struct session *session, DNDSMessage_t *req_msg)
{
	PeerConnectInfo_printf(req_msg);
}

void authRequest(struct session *session, DNDSMessage_t *req_msg)
{
	char *certName;
	size_t length;
	AuthRequest_get_certName(req_msg, &certName, &length);

	// XXX validate the certName
	// fetch the appropriate certificate
	// step_up the security
	printf("certName: %s\n", certName);

	// XXX mark the session as authenticated
	session->status = SESSION_STATUS_AUTHED;

	// XXX answer the client
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 1);
	DSMessage_set_operation(msg, dsop_PR_authResponse);
	AuthResponse_set_result(msg, DNDSResult_success);

	net_send_msg(session->netc, msg);
}

void addRequest(struct session *session, DNDSMessage_t *msg)
{

}

void delRequest(struct session *session, DNDSMessage_t *msg)
{

}

void modifyRequest(struct session *session, DNDSMessage_t *msg)
{

}

/* XXX This is a prototype, it only handle context object,
 * with a request type set to all. Will be expanded in near future...
 */
void searchRequest(struct session *session, DNDSMessage_t *req_msg)
{
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
        DSMessage_set_operation(msg, dsop_PR_searchResponse);

        SearchResponse_set_result(msg, DNDSResult_success);

        DNDSObject_t *objContext;
        DNDSObject_new(&objContext);
        DNDSObject_set_objectType(objContext, DNDSObject_PR_context);

        Context_set_id(objContext, atoi(id));
        Context_set_topology(objContext, Topology_mesh);
        Context_set_description(objContext, description, strlen(description));
        Context_set_network(objContext, network);
        Context_set_netmask(objContext, netmask);
        Context_set_serverCert(objContext, serverCert, strlen(serverCert));
        Context_set_serverPrivkey(objContext, serverPrivkey, strlen(serverPrivkey));
        Context_set_trustedCert(objContext, trustedCert, strlen(trustedCert));

        SearchResponse_add_object(msg, objContext);

	net_send_msg(session->netc, msg);
}