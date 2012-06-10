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
	/* XXX This is a prototype, it only handle client object
		and doesn't handle any error yet ... */

	/* XXX dispatch per object type */

	printf("add request!\n");

	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);


	DNDSObject_PR objType;
	AddRequest_get_objectType(msg, &objType);

	if (objType == DNDSObject_PR_client) {
		printf("add new client !\n");
	}

	size_t length;

        uint32_t id;
        Client_get_id(obj, &id);

        char *username;
        Client_get_username(obj, &username, &length);

        char *password;
        Client_get_password(obj, &password, &length);

        char *firstname;
        Client_get_firstname(obj, &firstname, &length);

        char *lastname;
        Client_get_lastname(obj, &lastname, &length);

        char *email;
        Client_get_email(obj, &email, &length);

        char *company;
        Client_get_company(obj, &company, &length);

        char *phone;
        Client_get_phone(obj, &phone, &length);

        char *country;
        Client_get_country(obj, &country, &length);

        char *stateProvince;
        Client_get_stateProvince(obj, &stateProvince, &length);

        char *city;
        Client_get_city(obj, &city, &length);

        char *postalCode;
        Client_get_postalCode(obj, &postalCode, &length);

        uint8_t status;
        Client_get_status(obj, &status);

	dao_add_client(firstname,
			lastname,
			email,
			company,
			phone,
			country,
			stateProvince,
			city,
			postalCode);


	char *client_id = NULL;
	dao_fetch_client_id(&client_id, firstname, lastname, email);

	dao_add_webcredential(client_id, username, password);

}

void delRequest(struct session *session, DNDSMessage_t *msg)
{

}

void modifyRequest(struct session *session, DNDSMessage_t *msg)
{

}

void searchRequest_context(struct session *session, DNDSMessage_t *req_msg)

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

void searchRequest_webcredential(struct session *session, DNDSMessage_t *req_msg)
{
	DNDSObject_t *object;

	SearchRequest_get_object(req_msg, &object);
	DNDSObject_printf(object);

        size_t length;

	char *id = NULL;

        char *username;
        WebCredential_get_username(object, &username, &length);
        printf("WebCredential> username: %s\n", username);

        char *password;
        WebCredential_get_password(object, &password, &length);
        printf("WebCredential> password: %s\n", password);

	dao_fetch_webcredential_client_id(&id, username, password);



        DNDSMessage_t *msg;

        DNDSMessage_new(&msg);
        DNDSMessage_set_channel(msg, 0);
        DNDSMessage_set_pdu(msg, pdu_PR_dsm);

        DSMessage_set_seqNumber(msg, 0);
        DSMessage_set_ackNumber(msg, 1);
        DSMessage_set_operation(msg, dsop_PR_searchResponse);

        SearchResponse_set_result(msg, DNDSResult_success);

        DNDSObject_t *objWebCred;
        DNDSObject_new(&objWebCred);
        DNDSObject_set_objectType(objWebCred, DNDSObject_PR_webcredential);

        WebCredential_set_clientId(objWebCred, atoi(id));

        SearchResponse_add_object(msg, objWebCred);

	net_send_msg(session->netc, msg);
}

/* XXX This is a prototype, it only handle context object,
 * with a request type set to all. Will be expanded in near future...
 */
void searchRequest(struct session *session, DNDSMessage_t *req_msg)
{
	e_SearchType SearchType;

	SearchRequest_get_searchType(req_msg, &SearchType);

	printf("SearchType: %s\n", SearchType_str(SearchType));

	if (SearchType == SearchType_all) {

		searchRequest_context(session, req_msg);
	}

	if (SearchType == SearchType_object) {
		searchRequest_webcredential(session, req_msg);
	}

}
