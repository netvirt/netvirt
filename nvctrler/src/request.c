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

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);

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
	embassy_id = pki_digital_id("embassy", "CA", "Quebec", "", "admin@netvirt.org", "NetVirt");

	embassy_t *emb;
	emb = pki_embassy_new(embassy_id, exp_delay);
	free(embassy_id);

	char *emb_cert_ptr; long size;
	char *emb_pvkey_ptr;

	pki_write_certificate_in_mem(emb->certificate, &emb_cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &emb_pvkey_ptr, &size);

	/* 3.2- Initialize server passport */

	digital_id_t *server_id;
	server_id = pki_digital_id("nvswitch", "CA", "Quebec", "", "admin@netvirt.org", "NetVirt");

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

	/* Create an IP pool */
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

	DNDSObject_t *obj;
	AddRequest_get_object(msg, &obj);

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
	unsigned char *ippool_bin = NULL;
	long size;

	char *uuid = NULL;
	char *provcode = NULL;
	char common_name[256] = {0};
	char *node_cert_ptr = NULL;
	char *node_pvkey_ptr = NULL;
	char emb_serial[10];

	Node_get_contextId(obj, &context_id);
	Node_get_description(obj, &description, &length);

	snprintf(context_id_str, 10, "%d", context_id);

	exp_delay = pki_expiration_delay(10);
	ret = dao_fetch_context_embassy(context_id_str, &emb_cert_ptr, &emb_pvkey_ptr, &serial, &ippool_bin);
	if (ret == -1) {
		jlog(L_ERROR, "failed to fetch context embassy");
		return;
	}
	jlog(L_DEBUG, "serial: %s", serial);

	emb = pki_embassy_load_from_memory(emb_cert_ptr, emb_pvkey_ptr, atoi(serial));

	uuid = uuid_v4();
	provcode = uuid_v4();

	snprintf(common_name, sizeof(common_name), "nva-%s@%s", uuid, context_id_str);
	jlog(L_DEBUG, "common_name: %s", common_name);

	digital_id_t *node_ident = NULL;
	node_ident = pki_digital_id(common_name, "", "", "", "admin@netvirt.org", "NetVirt");

	passport_t *node_passport = NULL;
	node_passport = pki_embassy_deliver_passport(emb, node_ident, exp_delay);

	/* FIXME verify is the value is freed or not via BIO_free() */
	pki_write_certificate_in_mem(node_passport->certificate, &node_cert_ptr, &size);
	pki_write_privatekey_in_mem(node_passport->keyring, &node_pvkey_ptr, &size);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);

	ret = dao_update_embassy_serial(context_id_str, emb_serial);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy serial");
		goto free1;
	}
	jlog(L_DEBUG, "dao_update_embassy_serial: %d", ret);

	/* handle ip pool */
	struct ippool *ippool;
	char *ip;
	int pool_size;

	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ip = ippool_get_ip(ippool);

	ret = dao_add_node(context_id_str, uuid, node_cert_ptr, node_pvkey_ptr, provcode, description, ip);
	if (ret == -1) {
		jlog(L_ERROR, "failed to add node");
		goto free2;
	}

	ret = dao_update_context_ippool(context_id_str, ippool->pool, pool_size);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy ippool");
		goto free2;
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

free2:
	ippool_free(ippool);

free1:
	free(node_passport);
	free(node_ident);

	free(uuid);
	free(provcode);

	free(node_cert_ptr);
	free(node_pvkey_ptr);

	free(serial);
	free(emb);
	free(emb_cert_ptr);
	free(emb_pvkey_ptr);
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

void CB_searchRequest_context(void *data, int remaining,
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
	static DNDSMessage_t *msg = NULL;
	static int count = 0;
	struct session *session = (struct session *)data;

	count++;

	if (msg == NULL) {

		DNDSMessage_new(&msg);
		DNDSMessage_set_channel(msg, 0);
		DNDSMessage_set_pdu(msg, pdu_PR_dsm);

		DSMessage_set_seqNumber(msg, 0);
		DSMessage_set_ackNumber(msg, 1);
		DSMessage_set_operation(msg, dsop_PR_searchResponse);

		SearchResponse_set_searchType(msg, SearchType_all);
	}

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

	if (count == 10 || remaining == 0) {

		if (remaining == 0) {
			SearchResponse_set_result(msg, DNDSResult_success);
		} else {
			SearchResponse_set_result(msg, DNDSResult_moreData);
		}

		net_send_msg(session->netc, msg);
		DNDSMessage_del(msg);
		msg = NULL;

		count = 0;
	}
}

void searchRequest_context(struct session *session)
{
	dao_fetch_context(session, CB_searchRequest_context);
}

void CB_searchRequest_node_sequence(void *data, int remaining, char *uuid, char *context_id)
{
	static DNDSMessage_t *msg = NULL;
	static int count = 0;
	struct session *session = (struct session *)data;

	count++;

	if (msg == NULL) {

		DNDSMessage_new(&msg);
		DNDSMessage_set_pdu(msg, pdu_PR_dsm);
		DSMessage_set_operation(msg, dsop_PR_searchResponse);
		SearchResponse_set_searchType(msg, SearchType_sequence);
	}

	DNDSObject_t *objNode;
	DNDSObject_new(&objNode);
	DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

	Node_set_uuid(objNode, uuid, strlen(uuid));
	Node_set_contextId(objNode, atoi(context_id));

	SearchResponse_add_object(msg, objNode);

	if (count == 10 || remaining == 0) {

		if (remaining == 0) {
			SearchResponse_set_result(msg, DNDSResult_success);
		} else {
			SearchResponse_set_result(msg, DNDSResult_moreData);
		}

		net_send_msg(session->netc, msg);
		DNDSMessage_del(msg);

		msg = NULL;
		count = 0;
	}
}

void searchRequest_node_sequence(struct session *session, DNDSMessage_t *req_msg)
{
	/* extract the list of node context id from the req_msg */
	DNDSObject_t *object = NULL;
	uint32_t count = 0;
	uint32_t i = 0;
	uint32_t *id_list = NULL;
	uint32_t contextId = 0;
	int ret = 0;

	SearchRequest_get_object_count(req_msg, &count);
	if (count == 0) {
		/* XXX send failed reply */
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

	/* sql query that return all the node uuid */
	dao_fetch_node_sequence(id_list, count, session, CB_searchRequest_node_sequence);

	free(id_list);
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
