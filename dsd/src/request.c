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

#include <stdlib.h>

#include <dnds/dnds.h>

#include "dao.h"
#include "request.h"


/* TODO this prototype is highly fragile,
 * we must handle all errors */

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

void AddRequest_peer(struct session *session, DNDSMessage_t *msg)
{
	printf("Add Peer !\n");

	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

	size_t length = 0;

	uint32_t contextId = 0;
	Peer_get_contextId(obj, &contextId);

	char *description = NULL;
	Peer_get_description(obj, &description, &length);

	char str_ctxid[10];
	snprintf(str_ctxid, 10, "%d", contextId);

	/* DNC certificate */

	pki_init();

	int exp_delay;
	exp_delay = pki_expiration_delay(50);

	char *cert_ptr; long size;
	char *pvkey_ptr;



	// fetch embassy
	char *certificate, *private_key, *serial;
	embassy_t *f_emb;
	dao_fetch_embassy(str_ctxid, &certificate, &private_key, &serial);

	f_emb = pki_embassy_load_from_memory(certificate, private_key, atoi(serial));

	char *uuid;
	uuid = uuid_v4();

	char *provcode;
	provcode = uuid_v4();

	char common_name[256];
	snprintf(common_name, sizeof(common_name), "dnc-%s@%s", uuid, str_ctxid);
	printf("common_name: %s\n", common_name);

	digital_id_t *dnc_id;
	dnc_id = pki_digital_id(common_name, "CA", "Quebec", "Levis", "info@demo.com", "DNDS");

	passport_t *dnc_passport;
	dnc_passport = pki_embassy_deliver_passport(f_emb, dnc_id, exp_delay);

	pki_write_certificate_in_mem(dnc_passport->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(dnc_passport->keyring, &pvkey_ptr, &size);

	dao_add_passport_client(str_ctxid, uuid, cert_ptr, pvkey_ptr, provcode);

	dao_update_embassy_issue_serial(str_ctxid, f_emb->serial);

	free(cert_ptr);
	free(pvkey_ptr);
}

void AddRequest_client(struct session *session, DNDSMessage_t *msg)
{
	printf("Add Request !\n");

	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);


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

void AddRequest_context(struct session *session, DNDSMessage_t *msg)
{
	printf("Add context!\n");


	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

	size_t length;

	uint32_t clientId;
	Context_get_clientId(obj, &clientId);

	char *description = NULL;
	Context_get_description(obj, &description, &length);

	printf("description: %s\n", description);

	char str_id[10];
	snprintf(str_id, 10, "%d", clientId);

	printf("str_id: %s\n", str_id);

	dao_add_context(str_id, 1, description);

	char *context_id = NULL;
	dao_fetch_context_id(&context_id, str_id, description);

	char network[INET_ADDRSTRLEN];
	Context_get_network(obj, network);

	char netmask[INET_ADDRSTRLEN];
	Context_get_netmask(obj, netmask);

	printf("network || netmask: %s || %s \n", network, netmask);

	/* XXX the network/netmask we receive is buggy..
	 * DSC python code has a problem...
	 * use default values for now
	 */
	dao_add_subnet(context_id, "44.128.0.0", "255.255.0.0");

	/* DSD certificate */

	pki_init();

	int exp_delay;
	exp_delay = pki_expiration_delay(50);

	digital_id_t *dsd_id;

	dsd_id = pki_digital_id("embassy", "CA", "Quebec", "Levis", "info@demo.com", "DNDS");

	embassy_t *emb;
	emb = pki_embassy_new(dsd_id, exp_delay);

	char *cert_ptr; long size;
	char *pvkey_ptr;

	pki_write_certificate_in_mem(emb->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &pvkey_ptr, &size);

	dao_add_embassy(context_id, cert_ptr, pvkey_ptr);

	free(cert_ptr);
	free(pvkey_ptr);

	/* DND certificate */

	digital_id_t *dnd_id;
	dnd_id = pki_digital_id("dnd", "CA", "Quebec", "Levis", "info@demo.com", "DNDS");

	passport_t *dnd_passport;
	dnd_passport = pki_embassy_deliver_passport(emb, dnd_id, exp_delay);

	pki_write_certificate_in_mem(dnd_passport->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(dnd_passport->keyring, &pvkey_ptr, &size);

	char common_name[20];
	snprintf(common_name, 20, "dnd@%s", context_id);

	dao_add_passport_server(context_id, common_name, cert_ptr, pvkey_ptr);

	free(cert_ptr);
	free(pvkey_ptr);
}

void addRequest(struct session *session, DNDSMessage_t *msg)
{

	DNDSObject_PR objType;
	AddRequest_get_objectType(msg, &objType);

	if (objType == DNDSObject_PR_client) {
		AddRequest_client(session, msg);
	}

	if (objType == DNDSObject_PR_context) {
		AddRequest_context(session, msg);
	}

	if (objType == DNDSObject_PR_peer) {
		AddRequest_peer(session, msg);
	}
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

	printf("id: %s:%d\n", id, atoi(id));

        Context_set_id(objContext, atoi(id));
        Context_set_topology(objContext, Topology_mesh);
        Context_set_description(objContext, description, strlen(description));
        Context_set_network(objContext, network);
        Context_set_netmask(objContext, netmask);
        Context_set_serverCert(objContext, serverCert, strlen(serverCert));
        Context_set_serverPrivkey(objContext, serverPrivkey, strlen(serverPrivkey));
        Context_set_trustedCert(objContext, trustedCert, strlen(trustedCert));

	SearchResponse_set_searchType(msg, SearchType_all);
        SearchResponse_add_object(msg, objContext);

	net_send_msg(session->netc, msg);

}

void searchRequest_peer(struct session *session, DNDSMessage_t *req_msg)
{
	printf("searchRequest peer for provisioning !\n");


	char *provcode = NULL;
	uint32_t length;

	DNDSObject_t *obj;
        SearchRequest_get_object(req_msg, &obj);
	Peer_get_provCode(obj, &provcode, &length);
	printf("provcode to search: %s\n", provcode);


	//// answer ////
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_searchResponse);

	SearchResponse_set_result(msg, DNDSResult_success);

	DNDSObject_t *objPeer;
	DNDSObject_new(&objPeer);
	DNDSObject_set_objectType(objPeer, DNDSObject_PR_peer);

	char *certificate = NULL;
	char *private_key = NULL;
	char *trustedcert = NULL;

	dao_fetch_peer_from_provcode(provcode, &certificate, &private_key, &trustedcert);

	Peer_set_certificate(objPeer, certificate, strlen(certificate));
	Peer_set_certificateKey(objPeer, private_key, strlen(private_key));
	Peer_set_trustedCert(objPeer, trustedcert, strlen(trustedcert));

	SearchResponse_set_searchType(msg, SearchType_object);
	SearchResponse_add_object(msg, objPeer);
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

	SearchResponse_set_searchType(msg, SearchType_all);
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
	DNDSObject_t *object;
	DNDSObject_PR objType;


	SearchRequest_get_searchType(req_msg, &SearchType);

	printf("SearchType: %s\n", SearchType_str(SearchType));

	if (SearchType == SearchType_all) {

		searchRequest_context(session, req_msg);
	}

	if (SearchType == SearchType_object) {

		SearchRequest_get_object(req_msg, &object);
	        DNDSObject_get_objectType(object, &objType);

		switch (objType) {
		case DNDSObject_PR_webcredential:
			searchRequest_webcredential(session, req_msg);
			break;
		case DNDSObject_PR_peer:
			searchRequest_peer(session, req_msg);
			break;
		}
	}
}
