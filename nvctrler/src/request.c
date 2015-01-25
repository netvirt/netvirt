/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnds.h>
#include <logger.h>

#include "dao.h"
#include "ippool.h"
#include "pki.h"
#include "request.h"

int CB_searchRequest_context_by_client_id(void *msg,
						char *id,
						char *description,
						char *client_id,
						char *network,
						char *netmask,
						char *serverCert,
						char *serverPrivkey,
						char *trustedCert)
{
	DNDSMessage_printf(msg);
	DNDSObject_t *objContext;
	DNDSObject_new(&objContext);
	DNDSObject_set_objectType(objContext, DNDSObject_PR_context);

	Context_set_id(objContext, atoi(id));
	Context_set_clientId(objContext, atoi(client_id));
	Context_set_description(objContext, description, strlen(description));
	Context_set_network(objContext, network);
	Context_set_netmask(objContext, netmask);

	Context_set_serverCert(objContext, serverCert, strlen(serverCert));
	Context_set_serverPrivkey(objContext, serverPrivkey, strlen(serverPrivkey));
	Context_set_trustedCert(objContext, trustedCert, strlen(trustedCert));

	SearchResponse_add_object(msg, objContext);

	return 0;
}

void nodeConnectInfo(struct session *session, DNDSMessage_t *req_msg)
{
	(void)(session);

	size_t length;
	char *certName;
	char ipAddress[INET_ADDRSTRLEN];
	e_ConnectState state;
	char *uuid = NULL;
	char *context_id = NULL;
	char *ptr = NULL;

	NodeConnectInfo_get_certName(req_msg, &certName, &length);
	NodeConnectInfo_get_ipAddr(req_msg, ipAddress);
	NodeConnectInfo_get_state(req_msg, &state);

	uuid = strdup(certName+4);
	ptr = strchr(uuid, '@');
	*ptr = '\0';
	context_id = strdup(ptr+1);

	switch(state) {
	case ConnectState_connected:
		dao_update_node_status(context_id, uuid, "1", ipAddress);
		break;
	case ConnectState_disconnected:
		dao_update_node_status(context_id, uuid, "0", ipAddress);
		break;
	default:
		jlog(L_WARNING, "the connection state is invalid");
		break;
	}

	free(uuid);
	free(context_id);

	return;
}

void AddRequest_client(DNDSMessage_t *msg)
{
	jlog(L_DEBUG, "Add Request client");

	DNDSMessage_printf(msg);
	DSMessage_printf(msg);
	AddRequest_printf(msg);

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

	int ret = 0;
	size_t length = 0;

	char *email = NULL;
	char *password = NULL;

        Client_get_password(obj, &password, &length);
        Client_get_email(obj, &email, &length);

	ret = dao_add_client(email, password);

	if (ret == -1) {
		jlog(L_ERROR, "failed to add client");
		return;
	}
}

void AddRequest_context(DNDSMessage_t *msg)
{
	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);
	DNDSObject_printf(obj);

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

	/* initialize embassy */
	int exp_delay;
	exp_delay = pki_expiration_delay(10);

	digital_id_t *embassy_id;
	embassy_id = pki_digital_id("nvctrler", "", "", "", "admin@netvirt.org", "www.netvirt.org");

	embassy_t *emb;
	emb = pki_embassy_new(embassy_id, exp_delay);
	free(embassy_id);

	char *emb_cert_ptr; long size;
	char *emb_pvkey_ptr;

	pki_write_certificate_in_mem(emb->certificate, &emb_cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &emb_pvkey_ptr, &size);

	/* initialize nvswitch passport */
	digital_id_t *server_id;
	server_id = pki_digital_id("nvswitch", "", "", "", "admin@netvirt.org", "www.netvirt.org");

	passport_t *nvswitch_passport;
	nvswitch_passport = pki_embassy_deliver_passport(emb, server_id, exp_delay);
	free(server_id);

	char *serv_cert_ptr;
	char *serv_pvkey_ptr;

	pki_write_certificate_in_mem(nvswitch_passport->certificate, &serv_cert_ptr, &size);
	pki_write_privatekey_in_mem(nvswitch_passport->keyring, &serv_pvkey_ptr, &size);
	free(nvswitch_passport);

	char emb_serial[10];
	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);
	free(emb);

	/* create an IP pool */
	struct ippool *ippool;
	size_t pool_size;

	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);

	dao_add_context(client_id_str,
				description,
				"44.128.0.0/16",
				emb_cert_ptr,
				emb_pvkey_ptr,
				emb_serial,
				serv_cert_ptr,
				serv_pvkey_ptr,
				ippool->pool,
				pool_size);

	ippool_free(ippool);

	free(serv_cert_ptr);
	free(serv_pvkey_ptr);

	free(emb_cert_ptr);
	free(emb_pvkey_ptr);

	/* send context update to nvswitch */

	DNDSMessage_t *msg_up;
	DNDSMessage_new(&msg_up);
	DNDSMessage_set_channel(msg_up, 0);
	DNDSMessage_set_pdu(msg_up, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg_up, 0);
	DSMessage_set_ackNumber(msg_up, 1);
	DSMessage_set_operation(msg_up, dsop_PR_searchResponse);

	dao_fetch_context_by_client_id_desc(client_id_str, description, msg_up,
		CB_searchRequest_context_by_client_id);

	SearchResponse_set_searchType(msg_up, SearchType_all);
	SearchResponse_set_result(msg_up, DNDSResult_success);

	if (g_switch_netc)
		net_send_msg(g_switch_netc, msg_up);

	DNDSMessage_del(msg_up);
}

void DelRequest_context(DNDSMessage_t *msg)
{
	DNDSObject_t *object;
	DelRequest_get_object(msg, &object);

	int ret = 0;
	uint32_t contextId = -1;
	char context_id_str[10] = {0};
	Context_get_id(object, &contextId);
	snprintf(context_id_str, 10, "%d", contextId);

	jlog(L_NOTICE, "deleting nodes belonging to context: %s", context_id_str);
	ret = dao_del_node_by_context_id(context_id_str);
	if (ret < 0) {
		jlog(L_NOTICE, "deleting nodes failed!");
		return;
	}

	jlog(L_NOTICE, "deleting context: %s", context_id_str);
	ret = dao_del_context(context_id_str);
	if (ret < 0) {
		/* FIXME: multiple DAO calls should be commited to the DB once
		 * all calls have succeeded.
		 */
		jlog(L_NOTICE, "deleting context failed!");
		return;
	}

	/* forward the delRequest to nvswitch */
	if (g_switch_netc)
		net_send_msg(g_switch_netc, msg);
}

void AddRequest_node(DNDSMessage_t *msg)
{
	jlog(L_DEBUG, "AddRequest_node");

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

	unsigned char *ippool_bin = NULL;

	char *uuid = NULL;
	char *provcode = NULL;

	Node_get_contextId(obj, &context_id);
	Node_get_description(obj, &description, &length);

	snprintf(context_id_str, 10, "%d", context_id);

	uuid = uuid_v4();
	provcode = uuid_v4();

	/* handle ip pool */
	struct ippool *ippool;
	char *ip;
	int pool_size;

	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ip = ippool_get_ip(ippool);

	ret = dao_add_node(context_id_str, uuid, provcode, description, ip);
	if (ret == -1) {
		jlog(L_ERROR, "failed to add node");
		goto err;
	}

	ret = dao_update_context_ippool(context_id_str, ippool->pool, pool_size);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy ippool");
		goto err;
	}


	/* send node update to nvswitch */

	DNDSMessage_t *msg_up;
	DNDSMessage_new(&msg_up);
	DNDSMessage_set_pdu(msg_up, pdu_PR_dsm);
	DSMessage_set_operation(msg_up, dsop_PR_searchResponse);
	SearchResponse_set_searchType(msg_up, SearchType_sequence);
	SearchResponse_set_result(msg_up, DNDSResult_success);

	DNDSObject_t *objNode;
	DNDSObject_new(&objNode);
	DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

	Node_set_uuid(objNode, uuid, strlen(uuid));
	Node_set_contextId(objNode, context_id);

	SearchResponse_add_object(msg_up, objNode);

	if (g_switch_netc)
		net_send_msg(g_switch_netc, msg_up);

	DNDSMessage_del(msg_up);

err:
	ippool_free(ippool);
	free(uuid);
	free(provcode);
}

void DelRequest_node(DNDSMessage_t *msg)
{
	DNDSObject_t *object;
	DelRequest_get_object(msg, &object);

	size_t length = 0;
	uint32_t contextId = -1;
	char context_id_str[10] = {0};
	Node_get_contextId(object, &contextId);
	snprintf(context_id_str, 10, "%d", contextId);

	char *uuid = NULL;
	Node_get_uuid(object, &uuid, &length);

	jlog(L_NOTICE, "revoking node: %s", uuid);
	dao_del_node(context_id_str, uuid);

	/* forward the delRequest to nvswitch */
	if (g_switch_netc)
		net_send_msg(g_switch_netc, msg);
}

void addRequest(DNDSMessage_t *msg)
{
	DNDSObject_PR objType;
	AddRequest_get_objectType(msg, &objType);

	if (objType == DNDSObject_PR_client) {
		AddRequest_client(msg);
	}

	if (objType == DNDSObject_PR_context) {
		AddRequest_context(msg);
	}

	if (objType == DNDSObject_PR_node) {
		AddRequest_node(msg);
	}
}

void delRequest(struct session *session, DNDSMessage_t *msg)
{
	(void)session;
	DNDSObject_PR objType;
	DelRequest_get_objectType(msg, &objType);

	if (objType == DNDSObject_PR_client) {
		/* FIXME : DelRequest_client(msg); */
	}

	if (objType == DNDSObject_PR_context) {
		DelRequest_context(msg);
	}

	if (objType == DNDSObject_PR_node) {
		DelRequest_node(msg);
	}
}

void modifyRequest(struct session *session, DNDSMessage_t *msg)
{
	(void)session;
	(void)msg;
}

void searchRequest_client(struct session *session, DNDSMessage_t *req_msg)
{
	DNDSObject_t *object;

	SearchRequest_get_object(req_msg, &object);
	DNDSObject_printf(object);

	size_t length;
	char *id = NULL;

	char *email;
	char *password;

	Client_get_email(object, &email, &length);
	Client_get_password(object, &password, &length);

	dao_fetch_client_id(&id, email, password);
	jlog(L_DEBUG, "client id: %s", id);

	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 1);
	DSMessage_set_operation(msg, dsop_PR_searchResponse);

	SearchResponse_set_searchType(msg, SearchType_object);
	SearchResponse_set_result(msg, DNDSResult_success);

	DNDSObject_t *objClient;
	DNDSObject_new(&objClient);
	DNDSObject_set_objectType(objClient, DNDSObject_PR_client);

	Client_set_id(objClient, id ? atoi(id): 0); /* FIXME set the result to failed if id == NULL */

	SearchResponse_add_object(msg, objClient);
	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
	free(id);
}

void searchRequest_context_by_client_id(struct session *session, DNDSMessage_t *req_msg)
{
	uint32_t client_id = 0;
	char str_client_id[20];

	DNDSObject_t *obj = NULL;
	SearchRequest_get_object(req_msg, &obj);

	Context_get_clientId(obj, &client_id);
	snprintf(str_client_id, sizeof(str_client_id), "%d", client_id);

	DNDSMessage_t *msg;
	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 1);
	DSMessage_set_operation(msg, dsop_PR_searchResponse);

	dao_fetch_context_by_client_id(str_client_id, msg,
		CB_searchRequest_context_by_client_id);

	SearchResponse_set_searchType(msg, SearchType_object);
	SearchResponse_set_result(msg, DNDSResult_success);

	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
}

void CB_searchRequest_context(void *msg,
				char *id,
				char *description,
				char *client_id,
				char *network,
				char *netmask,
				char *serverCert,
				char *serverPrivkey,
				char *trustedCert)
{
	(void)(client_id);

	DNDSObject_t *objContext;
	DNDSObject_new(&objContext);
	DNDSObject_set_objectType(objContext, DNDSObject_PR_context);

	Context_set_id(objContext, atoi(id));
	Context_set_description(objContext, description, strlen(description));
	Context_set_network(objContext, network);
	Context_set_netmask(objContext, netmask);
	Context_set_serverCert(objContext, serverCert, strlen(serverCert));
	Context_set_serverPrivkey(objContext, serverPrivkey, strlen(serverPrivkey));
	Context_set_trustedCert(objContext, trustedCert, strlen(trustedCert));

	SearchResponse_add_object(msg, objContext);
}

void searchRequest_context(struct session *session)
{
        DNDSMessage_t *msg;
        DNDSMessage_new(&msg);
        DNDSMessage_set_channel(msg, 0);
        DNDSMessage_set_pdu(msg, pdu_PR_dsm);

        DSMessage_set_seqNumber(msg, 0);
        DSMessage_set_ackNumber(msg, 1);
        DSMessage_set_operation(msg, dsop_PR_searchResponse);

        SearchResponse_set_result(msg, DNDSResult_success);

	dao_fetch_context(msg, CB_searchRequest_context);

	SearchResponse_set_searchType(msg, SearchType_all);

	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
}

void CB_searchRequest_node_sequence(void *msg, char *uuid, char *context_id)
{
	DNDSObject_t *objNode;
	DNDSObject_new(&objNode);
	DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

	Node_set_uuid(objNode, uuid, strlen(uuid));
	Node_set_contextId(objNode, atoi(context_id));

	SearchResponse_add_object(msg, objNode);
}

void searchRequest_node_sequence(struct session *session, DNDSMessage_t *req_msg)
{
	DNDSObject_t *object = NULL;
	uint32_t count = 0;
	uint32_t i = 0;
	uint32_t *id_list = NULL;
	uint32_t contextId = 0;
	int ret = 0;

	DNDSMessage_t *msg;
	DNDSMessage_new(&msg);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);
	DSMessage_set_operation(msg, dsop_PR_searchResponse);
	SearchResponse_set_searchType(msg, SearchType_sequence);
	SearchResponse_set_result(msg, DNDSResult_success);

	SearchRequest_get_object_count(req_msg, &count);
	if (count == 0) {
		net_send_msg(session->netc, msg);
		DNDSMessage_del(msg);
		return;
	}

	id_list = calloc(count, sizeof(uint32_t));
	for (i = 0; i < count; i++) {

		ret = SearchRequest_get_from_objects(req_msg, &object);
		if (ret == DNDS_success && object != NULL) {
			Node_get_contextId(object, &contextId);
			id_list[i] = contextId;
		}
		else {
			/* XXX send failed reply */
		}
	}

	dao_fetch_node_sequence(id_list, count, msg, CB_searchRequest_node_sequence);

	free(id_list);

	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
}

int CB_searchRequest_node_by_context_id(void *msg, char *uuid, char *description, char *provcode, char *ipaddress, char *status)
{
	DNDSObject_t *objNode;
	DNDSObject_new(&objNode);
	DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

	Node_set_description(objNode, description, strlen(description));
	Node_set_uuid(objNode, uuid, strlen(uuid));
	Node_set_provCode(objNode, provcode, strlen(provcode));
	Node_set_ipAddress(objNode, ipaddress);
	Node_set_status(objNode, atoi(status));

	SearchResponse_set_searchType(msg, SearchType_object);
	SearchResponse_add_object(msg, objNode);

	return 0;
}

void
provRequest(struct session *session, DNDSMessage_t *req_msg)
{
	int ret = 0;
	char *provcode = NULL;
	char *certreq_pem = NULL;
	size_t certreq_len = 0;
	size_t provcode_len = 0;
	uint32_t tracked_id = 0;

	X509_REQ *certreq = NULL; /* Certificate signing request */
	X509_NAME *name = NULL;
	char cn[128];
	node_info_t *node_info = NULL;

	(void)session;

	DNMessage_get_seqNumber(req_msg, &tracked_id);
	ProvRequest_get_certreq(req_msg, &certreq_pem, &certreq_len);
	ProvRequest_get_provCode(req_msg, &provcode, &provcode_len);


	certreq = pki_load_csr_from_memory(certreq_pem);
	name = X509_REQ_get_subject_name(certreq);
	X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));

	node_info = cn2node_info(cn);
	if (node_info == NULL) {
		jlog(L_WARNING, "the common name <%s> is malformed", cn);
		goto out0;
	}

	if (strncmp(node_info->type, "nva", 3) != 0) {
		jlog(L_WARNING, "the common name <%s> is invalid", cn);
		goto out;
	}

	jlog(L_DEBUG, "type: %s", node_info->type);
	jlog(L_DEBUG, "uuid: %s", node_info->uuid);

	char *context_id = NULL;
	char *certificate = NULL;
	char *privatekey = NULL;
	char *ipaddr = NULL;
	char *issue_serial = NULL;

	ret = dao_fetch_context_embassy_by_provisioning(node_info->uuid, provcode,
			&context_id, &certificate, &privatekey, &issue_serial, &ipaddr);
	if (ret != 0) {
		jlog(L_WARNING, "failed to fetch the context embassy");
		goto out;
	}

	if (strncmp(node_info->context_id, context_id, sizeof(node_info->context_id)) != 0) {
		jlog(L_WARNING, "the context id <%s> doesn't match <%s>", node_info->context_id, context_id);
		goto out;
	}

	jlog(L_DEBUG, "ctx id: %s", context_id);

	embassy_t *embassy = NULL;
	int exp_delay = 0;
	X509 *cert = NULL;
	X509_NAME *issuer = NULL;
	char emb_serial[10];
	char *cert_pem = NULL;
	long cert_pem_len = 0;

	embassy = pki_embassy_load_from_memory(certificate, privatekey, atoi(emb_serial));
	exp_delay = pki_expiration_delay(10);
	issuer = X509_get_subject_name(embassy->certificate);

	cert = pki_certificate(issuer, certreq, false, embassy->serial, exp_delay);
	pki_sign_certificate(embassy->keyring, cert);

	snprintf(emb_serial, sizeof(emb_serial), "%d", atoi(emb_serial)+1);
	ret = dao_update_embassy_serial(context_id, emb_serial);

	pki_write_certificate_in_mem(cert, &cert_pem, &cert_pem_len);

	DNDSMessage_t *new_msg = NULL;
	DNDSMessage_new(&new_msg);
	DNDSMessage_set_channel(new_msg, 0);
	DNDSMessage_set_pdu(new_msg, pdu_PR_dnm);

	DNMessage_set_operation(new_msg, dnop_PR_provResponse);
	DNMessage_set_seqNumber(new_msg, tracked_id);
	ProvResponse_set_certificate(new_msg, cert_pem, strlen(cert_pem));
	ProvResponse_set_trustedCert(new_msg, (uint8_t*)certificate, strlen(certificate));
	ProvResponse_set_ipAddress(new_msg, ipaddr);

	net_send_msg(session->netc, new_msg);
	DNDSMessage_del(new_msg);

	/*
	verify the cert common-name [x]
	fetch the context certs that has a node node with node-UUID + prov-UUID [x]
	verify if the context id match [x]
	load embassy in structure [x]
	create certificate [x]
	sign the cert req [x]
	update the serial number [x]
	build provResponse, populate it, and send it back to the switch [x]
	move CSR related stuff into pki
	*/

out:
	node_info_destroy(node_info);
out0:
	return;
}

void searchRequest_node(struct session *session, DNDSMessage_t *req_msg)
{
	char *provcode = NULL;
	uint32_t contextid = 0;
	char str_contextid[20];
	size_t length;
	int ret = 0;

	DNDSObject_t *obj = NULL;
        SearchRequest_get_object(req_msg, &obj);
	Node_get_provCode(obj, &provcode, &length);
	Node_get_contextId(obj, &contextid);

	uint32_t tracked_id;
	DSMessage_get_seqNumber(req_msg, &tracked_id);


	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, tracked_id);
	DSMessage_set_ackNumber(msg, 0);
	DSMessage_set_operation(msg, dsop_PR_searchResponse);

	if (contextid > 0) { /* searching by context ID */

		jlog(L_DEBUG, "context ID to search: %d", contextid);
		snprintf(str_contextid, sizeof(str_contextid), "%d", contextid);

		ret = dao_fetch_node_from_context_id(str_contextid, msg,
					CB_searchRequest_node_by_context_id);
		if (ret != 0) {
			jlog(L_WARNING, "dao fetch node from context id failed: %d", contextid);
			return; /* FIXME send negative response */
		}

		/* the fields are set via the callback */

	} else if (provcode != NULL) { /* searching by provcode */

		jlog(L_DEBUG, "searchRequest node for provisioning");

		DNDSObject_t *objNode;
		DNDSObject_new(&objNode);
		DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

		jlog(L_DEBUG, "provcode to search: %s", provcode);

		char *certificate = NULL;
		char *private_key = NULL;
		char *trustedcert = NULL;
		char *ipAddress = NULL;

		ret = dao_fetch_node_from_provcode(provcode, &certificate, &private_key, &trustedcert, &ipAddress);
		if (ret != 0) {
			SearchResponse_set_result(msg, DNDSResult_noSuchObject);
			SearchResponse_set_searchType(msg, SearchType_object);
			net_send_msg(session->netc, msg);
			DNDSMessage_del(msg);
			return;
		}

		Node_set_certificate(objNode, certificate, strlen(certificate));
		Node_set_certificateKey(objNode, (uint8_t*)private_key, strlen(private_key));
		Node_set_trustedCert(objNode, (uint8_t*)trustedcert, strlen(trustedcert));
		Node_set_ipAddress(objNode, ipAddress);

		SearchResponse_set_result(msg, DNDSResult_success);
		SearchResponse_add_object(msg, objNode);
	}

	SearchResponse_set_searchType(msg, SearchType_object);
	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
}

void searchRequest(struct session *session, DNDSMessage_t *req_msg)
{
	e_SearchType SearchType;
	DNDSObject_t *object;
	DNDSObject_PR objType;

	SearchRequest_get_searchType(req_msg, &SearchType);

	SearchRequest_get_object(req_msg, &object);
	DNDSObject_get_objectType(object, &objType);

	if (SearchType == SearchType_all) {
		searchRequest_context(session);
	}

	if (SearchType == SearchType_sequence) {
		searchRequest_node_sequence(session, req_msg);
	}

	if (SearchType == SearchType_object) {

		switch (objType) {
		case DNDSObject_PR_client:
			searchRequest_client(session, req_msg);
			break;
		case DNDSObject_PR_node:
			searchRequest_node(session, req_msg);
			break;
		case DNDSObject_PR_context:
			searchRequest_context_by_client_id(session, req_msg);
			break;
		case DNDSObject_PR_NOTHING:
			break;
		}
	}
}
