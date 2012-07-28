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
#include <dnds/journal.h>

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
	jlog(L_DEBUG, "certName: %s\n", certName);

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

void AddRequest_node(struct session *session, DNDSMessage_t *msg)
{
	jlog(L_NOTICE, "AddRequest_node!");
	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

	int ret = 0;
	size_t length = 0;

	uint32_t context_id = 0;
	char context_id_str[10] = {0};
	char *description = NULL;

	int exp_delay;
	embassy_t *emb = NULL;
	char *emb_cert_ptr = NULL;
	char *emb_pvkey_ptr = NULL;
	char *serial = NULL;
	long size;

	char *uuid = NULL;
	char *provcode = NULL;
	char common_name[256] = {0};
	char *node_cert_ptr = NULL;
	char *node_pvkey_ptr = NULL;
	char emb_serial[10];

	Peer_get_contextId(obj, &context_id);
	Peer_get_description(obj, &description, &length);

	snprintf(context_id_str, 10, "%d", context_id);

	exp_delay = pki_expiration_delay(10);
	ret = dao_fetch_context_embassy(context_id_str, &emb_cert_ptr, &emb_pvkey_ptr, &serial);
	if (ret == -1) {
		jlog(L_ERROR, "failed to fetch context embassy\n");
		return;
	}
	jlog(L_DEBUG, "serial: %s\n", serial);

	emb = pki_embassy_load_from_memory(emb_cert_ptr, emb_pvkey_ptr, atoi(serial));

	uuid = uuid_v4();
	provcode = uuid_v4();

	snprintf(common_name, sizeof(common_name), "dnc-%s@%s", uuid, context_id_str);
	jlog(L_DEBUG, "common_name: %s\n", common_name);

	digital_id_t *node_ident = NULL;
	node_ident = pki_digital_id(common_name, "", "", "", "info@dynvpn.com", "DNDS");

	passport_t *node_passport = NULL;
	node_passport = pki_embassy_deliver_passport(emb, node_ident, exp_delay);

	pki_write_certificate_in_mem(node_passport->certificate, &node_cert_ptr, &size);
	pki_write_privatekey_in_mem(node_passport->keyring, &node_pvkey_ptr, &size);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);
	printf("emb->serial: %d\n", emb->serial);

	ret = dao_update_embassy_serial(context_id_str, emb_serial);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy serial\n");
		return;
	}
	jlog(L_DEBUG, "dao_update_embassy_serial: %d\n", ret);

	ret = dao_add_node(context_id_str, uuid, node_cert_ptr, node_pvkey_ptr, provcode);
	if (ret == -1) {
		jlog(L_ERROR, "failed to add node\n");
		return;
	}

	free(uuid);
	free(provcode);

	free(serial);
	free(emb_cert_ptr);
	free(emb_pvkey_ptr);

	free(node_cert_ptr);
	free(node_pvkey_ptr);
}

void AddRequest_client(struct session *session, DNDSMessage_t *msg)
{
	jlog(L_DEBUG, "Add Request !\n");

	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

	int ret = 0;
	size_t length = 0;
	uint32_t id = 0;
	char *username = NULL;
	char *password = NULL;
	char *firstname = NULL;
	char *lastname = NULL;
	char *email = NULL;
	char *company = NULL;
	char *phone = NULL;
	char *country = NULL;
	char *stateProvince = NULL;
	char *city = NULL;
	char *postalCode = NULL;
	uint8_t status = 0;

        Client_get_id(obj, &id);
        Client_get_username(obj, &username, &length);
        Client_get_password(obj, &password, &length);
        Client_get_firstname(obj, &firstname, &length);
        Client_get_lastname(obj, &lastname, &length);
        Client_get_email(obj, &email, &length);
        Client_get_company(obj, &company, &length);
        Client_get_phone(obj, &phone, &length);
        Client_get_country(obj, &country, &length);
        Client_get_stateProvince(obj, &stateProvince, &length);
        Client_get_city(obj, &city, &length);
        Client_get_postalCode(obj, &postalCode, &length);
        Client_get_status(obj, &status);

	ret = dao_add_client(firstname,
			lastname,
			email,
			company,
			phone,
			country,
			stateProvince,
			city,
			postalCode,
			password);

	if (ret == -1) {
		jlog(L_ERROR, "failed to add client\n");
		return;
	}
}

void AddRequest_context(struct session *session, DNDSMessage_t *msg)
{
	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

	int ret;

	size_t length;

	uint32_t client_id;
	Context_get_clientId(obj, &client_id);

	char client_id_str[10];
	snprintf(client_id_str, 10, "%d", client_id);

	char *description = NULL;
	Context_get_description(obj, &description, &length);

	char network[INET_ADDRSTRLEN];
	Context_get_network(obj, network);

	char netmask[INET_ADDRSTRLEN];
	Context_get_netmask(obj, netmask);

	pki_init();

	/* 3.1- Initialise embassy */
	int exp_delay;
	exp_delay = pki_expiration_delay(10);

	digital_id_t *embassy_id;
	embassy_id = pki_digital_id("embassy", "CA", "Quebec", "Levis", "info@dynvpn.com", "DNDS");

	embassy_t *emb;
	emb = pki_embassy_new(embassy_id, exp_delay);

	char *emb_cert_ptr; long size;
	char *emb_pvkey_ptr;

	pki_write_certificate_in_mem(emb->certificate, &emb_cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &emb_pvkey_ptr, &size);

	/* 3.2- Initialise server passport */

	digital_id_t *server_id;
	server_id = pki_digital_id("dnd", "CA", "Quebec", "Levis", "info@dynvpn.com", "DNDS");

	passport_t *dnd_passport;
	dnd_passport = pki_embassy_deliver_passport(emb, server_id, exp_delay);

	char *serv_cert_ptr;
	char *serv_pvkey_ptr;

	pki_write_certificate_in_mem(dnd_passport->certificate, &serv_cert_ptr, &size);
	pki_write_privatekey_in_mem(dnd_passport->keyring, &serv_pvkey_ptr, &size);

	char emb_serial[10];
	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);

	ret = dao_add_context(client_id_str,
				description,
				"1",
				"44.128.0.0/16",
				emb_cert_ptr,
				emb_pvkey_ptr,
				emb_serial,
				serv_cert_ptr,
				serv_pvkey_ptr);

	printf("emb->serial: %d\n", emb->serial);
	printf("dao_add_context: %d\n", ret);

	free(serv_cert_ptr);
	free(serv_pvkey_ptr);

	free(emb_cert_ptr);
	free(emb_pvkey_ptr);

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
		AddRequest_node(session, msg);
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

	uint32_t tracked_id;
	DSMessage_get_seqNumber(req_msg, &tracked_id);

	//// answer ////
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, tracked_id);
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

	dao_fetch_client_id(&id, username, password);

	printf("id: %s\n", id);


        DNDSMessage_t *msg;

        DNDSMessage_new(&msg);
        DNDSMessage_set_channel(msg, 0);
        DNDSMessage_set_pdu(msg, pdu_PR_dsm);

        DSMessage_set_seqNumber(msg, 0);
        DSMessage_set_ackNumber(msg, 1);
        DSMessage_set_operation(msg, dsop_PR_searchResponse);

	SearchResponse_set_searchType(msg, SearchType_object);
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
