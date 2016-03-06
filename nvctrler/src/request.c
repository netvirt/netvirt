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

#include <jansson.h>
#include <event2/bufferevent.h>

#include <dnds.h>
#include <logger.h>

#include "dao.h"
#include "ippool.h"
#include "pki.h"
#include "request.h"

extern struct session_info *switch_sinfo;

void
update_node_status(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "update-node-status");

	char	*status;
	char	*local_ipaddr;
	char	*cert_name;
	char	*uuid = NULL;
	char	*netid = NULL;
	char	*ptr = NULL;

	json_t	*node;


	node = json_object_get(jmsg, "node");
	json_unpack(node, "{s:s}", "status", &status);
	json_unpack(node, "{s:s}", "local-ipaddr", &local_ipaddr);
	json_unpack(node, "{s:s}", "cert-name", &cert_name);

	uuid = strdup(cert_name+4);
	ptr = strchr(uuid, '@');
	*ptr = '\0';
	netid = strdup(ptr+1);

	dao_update_node_status(netid, uuid, status, local_ipaddr);

	free(uuid);
	free(netid);

	return;
}

void
delNetwork(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "del network");

	int		ret = 0;
	char		*client_id = NULL;
	char		*network_id = NULL;

	char		*apikey = NULL;
	char		*network_name = NULL;
	char		*fwd_str = NULL;
	char		*resp_str = NULL;
	json_t		*resp = NULL;
	json_t		*js_network = NULL;

	if ((js_network = json_object_get(jmsg, "network")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_network, "{s:s}", "name", &network_name);

	/* check apikey and name... */

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (client_id == NULL) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	ret = dao_fetch_network_id(&network_id, client_id, network_name);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}
	if (network_id == NULL) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}

	jlog(L_NOTICE, "deleting nodes belonging to context: %s", network_id);
	ret = dao_del_node_by_context_id(network_id);
	if (ret < 0) {
		jlog(L_NOTICE, "deleting nodes failed!");
		return;
	}

	jlog(L_NOTICE, "deleting context: %s", network_id);
	ret = dao_del_context(client_id, network_id);
	if (ret < 0) {
		/* FIXME: multiple DAO calls should be commited to the DB once
		 * all calls have succeeded.
		 */
		jlog(L_NOTICE, "deleting context failed!");
		return;
	}

	/* Forward del-network to the switch */
	json_object_del(jmsg, "apikey");
	json_object_del(js_network, "uuid");
	json_object_del(js_network, "name");
	json_object_set_new(js_network, "netid", json_string(network_id));

	fwd_str = json_dumps(jmsg, 0);
	bufferevent_write(switch_sinfo->bev, fwd_str, strlen(fwd_str));
	bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));
	free(fwd_str);
out:

	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);
	free(network_id);
}

void
addNode(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "add node");

	int		 ret = 0;
	char		*context_id = NULL;
	char		*client_id = NULL;
	char		*context_name = NULL;
	char		*description = NULL;

	int		 exp_delay;
	embassy_t	*emb = NULL;
	char		*emb_cert_ptr = NULL;
	char		*emb_pvkey_ptr = NULL;
	char		*serial = NULL;
	unsigned char	*ippool_bin = NULL;
	long		 size;

	char		*apikey = NULL;
	char		*uuid = NULL;
	char		*provcode = NULL;
	char		 common_name[256] = {0};
	char		*node_cert_ptr = NULL;
	char		*node_pvkey_ptr = NULL;
	char		 emb_serial[10];

	char		*resp_str = NULL;
	json_t		*resp = NULL;
	json_t		*js_node = NULL;

	struct ippool	*ippool = NULL;
	char		*ip = NULL;
	int		 pool_size;

	if ((js_node = json_object_get(jmsg, "node")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_node, "{s:s}", "networkname", &context_name);
	json_unpack(js_node, "{s:s}", "description", &description);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}

	ret = dao_fetch_network_id(&context_id, client_id, context_name);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}

	exp_delay = pki_expiration_delay(10);
	ret = dao_fetch_context_embassy(context_id, &emb_cert_ptr, &emb_pvkey_ptr, &serial, &ippool_bin);
	jlog(L_DEBUG, "serial: %s", serial);
	if (ret != 0) {
		jlog(L_ERROR, "failed to fetch context embassy");
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	emb = pki_embassy_load_from_memory(emb_cert_ptr, emb_pvkey_ptr, atoi(serial));

	uuid = uuid_v4();
	provcode = uuid_v4();

	snprintf(common_name, sizeof(common_name), "nva-%s@%s", uuid, context_id);
	jlog(L_DEBUG, "common_name: %s", common_name);

	digital_id_t *node_ident = NULL;
	node_ident = pki_digital_id(common_name, "", "", "", "admin@netvirt.org", "NetVirt");

	passport_t *node_passport = NULL;
	node_passport = pki_embassy_deliver_passport(emb, node_ident, exp_delay);

	/* FIXME verify is the value is freed or not via BIO_free() */
	pki_write_certificate_in_mem(node_passport->certificate, &node_cert_ptr, &size);
	pki_write_privatekey_in_mem(node_passport->keyring, &node_pvkey_ptr, &size);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);

	ret = dao_update_embassy_serial(context_id, emb_serial);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy serial");
		json_object_set_new(resp, "response", json_string("error"));
		goto free1;
	}

	/* handle ip pool */
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ip = ippool_get_ip(ippool);

	ret = dao_add_node(context_id, uuid, node_cert_ptr, node_pvkey_ptr, provcode, description, ip);
	if (ret == -1) {
		jlog(L_ERROR, "failed to add node");
		json_object_set_new(resp, "response", json_string("error"));
		goto free2;
	}

	ret = dao_update_context_ippool(context_id, ippool->pool, pool_size);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy ippool");
		json_object_set_new(resp, "response", json_string("error"));
		goto free2;
	}


	/* FIXME send node update to nvswitch */

	DNDSMessage_t *msg_up;
	DNDSMessage_new(&msg_up);
	DNDSMessage_set_pdu(msg_up, pdu_PR_dsm);
	DSMessage_set_action(msg_up, action_addNode);
	DSMessage_set_operation(msg_up, dsop_PR_searchResponse);
	SearchResponse_set_searchType(msg_up, SearchType_sequence);
	SearchResponse_set_result(msg_up, DNDSResult_success);

	DNDSObject_t *objNode;
	DNDSObject_new(&objNode);
	DNDSObject_set_objectType(objNode, DNDSObject_PR_node);

	Node_set_uuid(objNode, uuid, strlen(uuid));
	Node_set_contextId(objNode, atoi(context_id));

	SearchResponse_add_object(msg_up, objNode);

	if (g_switch_netc)
		net_send_msg(g_switch_netc, msg_up);

	DNDSMessage_del(msg_up);
	/* */

	json_object_set_new(resp, "response", json_string("success"));

free2:
	ippool_free(ippool);

free1:
	pki_passport_free(node_passport);
	pki_embassy_free(emb);
	pki_free_digital_id(node_ident);

	free(client_id);
	free(context_id);
	free(uuid);
	free(provcode);
	free(node_cert_ptr);
	free(node_pvkey_ptr);
	free(serial);
	free(emb_cert_ptr);
	free(emb_pvkey_ptr);

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
}

void
delNode(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "del node");

	int		ret = 0;
	char		*client_id = NULL;
	char		*network_id = NULL;
	char		*node_uuid = NULL;
	char		*apikey = NULL;
	char		*network_name = NULL;
	char		*resp_str = NULL;
	char		*fwd_str = NULL;
	char		*ipaddr = NULL;
	json_t		*js_node = NULL;
	json_t		*resp = NULL;
	struct ippool	*ippool = NULL;
	int		 pool_size;


	if ((js_node = json_object_get(jmsg, "node")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_node, "{s:s}", "networkname", &network_name);
	json_unpack(js_node, "{s:s}", "uuid", &node_uuid);

	/* check network_name and node_uuid */
	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));


	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}

	ret = dao_fetch_network_id(&network_id, client_id, network_name);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}

	ret = dao_fetch_node_ip(network_id, node_uuid, &ipaddr);
	if (ret != 0) {
		jlog(L_ERROR, "failed to fetch node ip");
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}

	jlog(L_NOTICE, "revoking node: %s, ip:%s, network:%s", node_uuid, ipaddr, network_id);
	dao_del_node(network_id, node_uuid);

	unsigned char *ippool_bin = NULL;
	ret = dao_fetch_context_ippool(network_id, &ippool_bin);
	if (ret == -1) {
		jlog(L_ERROR, "failed to fetch context ippool");
		return;
	}

	/* update ip pool */
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ippool_release_ip(ippool, ipaddr);

	ret = dao_update_context_ippool(network_id, ippool->pool, pool_size);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy ippool");
	}

	/* Forward del-node to the switch */
	json_object_del(jmsg, "apikey");
	json_object_del(js_node, "networkname");
	json_object_set_new(js_node, "netid", json_string(network_id));

	fwd_str = json_dumps(jmsg, 0);
	bufferevent_write(switch_sinfo->bev, fwd_str, strlen(fwd_str));
	bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));
	free(fwd_str);

out:

	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);
	free(network_id);
	free(ipaddr);
	ippool_free(ippool);

}

void delRequest(struct session *session, DNDSMessage_t *msg)
{
	(void)session;
	DNDSObject_PR objType;
	DelRequest_get_objectType(msg, &objType);

	if (objType == DNDSObject_PR_client) {
		/* FIXME : DelRequest_client(msg); */
	}
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
	DSMessage_set_action(msg, action_getAccountApiKey);
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

void
provisioning(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "provisioning");

	char	*cert;
	char	*pkey;
	char	*tcert;
	char	*ipaddr;

	char	*node;
	char	*provcode;
	char	*tid;
	char	*resp_str = NULL;
	char	*resp = NULL;

	json_unpack(jmsg, "{s:s}", "tid", &tid);

	node = json_object_get(jmsg, "node");
	json_unpack(node, "{s:s}", "provcode", &provcode);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string(tid));
	json_object_set_new(resp, "action", json_string("provisioning"));

	if ((dao_fetch_node_from_provcode(provcode, &cert, &pkey, &tcert, &ipaddr)) == 0) {
		json_object_set_new(resp, "response", json_string("success"));
		node = json_object();
		json_object_set_new(node, "cert", json_string(cert));
		json_object_set_new(node, "pkey", json_string(pkey));
		json_object_set_new(node, "tcert", json_string(tcert));
		json_object_set_new(node, "ipaddr", json_string(ipaddr));
		json_object_set_new(resp, "node", node);
	} else {
		json_object_set_new(resp, "response", json_string("error"));
	}

	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);

	return;
}

void
CB_listallNetwork(void *arg, int remaining,
				char *id,
				char *description,
				char *client_id,
				char *subnet,
				char *netmask,
				char *cert,
				char *pkey,
				char *tcert)
{
	char			*resp_str = NULL;
	struct session_info	*sinfo;
	json_t			*array;
	json_t			*network;
	json_t			*resp = NULL;

	sinfo = arg;
	network = json_object();
	array = json_array();
	resp = json_object();

	printf("uuid: %s\n", id);

	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("listall-network"));

	json_object_set_new(network, "uuid", json_string(id));
	json_object_set_new(network, "network", json_string(subnet));
	json_object_set_new(network, "netmask", json_string(netmask));
	json_object_set_new(network, "cert", json_string(cert));
	json_object_set_new(network, "pkey", json_string(pkey));
	json_object_set_new(network, "tcert", json_string(tcert));

	json_array_append_new(array, network);

	json_object_set_new(resp, "networks", array);
	if (remaining > 0)
		json_object_set_new(resp, "response", json_string("more-data"));
	else
		json_object_set_new(resp, "response", json_string("success"));

	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
}

void
listallNetwork(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "listallNetwork");

	char	*resp_str = NULL;
	json_t	*resp = NULL;

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("listall-network"));

	if (dao_fetch_context(sinfo, CB_listallNetwork) == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	return;
out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);

	return;
}

void
CB_listallNode(void *arg, int remaining, char *netid, char *uuid)
{
	char			*resp_str = NULL;
	struct	session_info	*sinfo;
	json_t			*array;
	json_t			*node;
	json_t			*resp = NULL;

	sinfo = arg;
	node = json_object();
	array = json_array();
	resp = json_object();

	printf("uuid: %s\n", uuid);
	printf("netid: %s\n", netid);

	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("listall-node"));

	json_object_set_new(node, "netid", json_string(netid));
	json_object_set_new(node, "uuid", json_string(uuid));

	json_array_append_new(array, node);

	json_object_set_new(resp, "nodes", array);
	if (remaining > 0)
		json_object_set_new(resp, "response", json_string("more-data"));
	else
		json_object_set_new(resp, "response", json_string("success"));

	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
}

void
listallNode(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "listallNode");

	char	*resp_str = NULL;
	json_t	*resp = NULL;

	dao_fetch_node_uuid_netid(sinfo, CB_listallNode);
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
		DSMessage_set_action(msg, action_listNode);
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
	static DNDSMessage_t *msg = NULL;
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
			DNDSObject_del(object);
			object = NULL;
		}
		else {
			/* XXX send failed reply */
		}
	}

	/* sql query that return all the node uuid */
	ret = dao_fetch_node_sequence(id_list, count, session, CB_searchRequest_node_sequence);
	if (ret == -1) {
		DNDSMessage_new(&msg);
		DNDSMessage_set_pdu(msg, pdu_PR_dsm);
		DSMessage_set_action(msg, action_listNode);
		DSMessage_set_operation(msg, dsop_PR_searchResponse);
		SearchResponse_set_searchType(msg, SearchType_sequence);

		SearchResponse_set_result(msg, DNDSResult_success);
		net_send_msg(session->netc, msg);
		DNDSMessage_del(msg);
	}

	free(id_list);
}

void
activateAccount(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "activate account");

	int	ret = 0;
	char	*email = NULL;
	char	*apikey = NULL;
	char	*new_apikey = NULL;
	char	*resp_str = NULL;
	json_t	*resp = NULL;
	json_t	*js_account = NULL;

	if ((js_account = json_object_get(jmsg, "account")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_account, "{s:s}", "email", &email);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	if (email == NULL) {
		jlog(L_ERROR, "Invalid message\n");
		return;
	}

	new_apikey = pki_gen_apikey();
	if (apikey == NULL) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	ret = dao_activate_client(email, apikey);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}

	dao_update_client_apikey(email, apikey, new_apikey);

	json_object_set_new(resp, "response", json_string("success"));

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(new_apikey);
	return;
}

void
addAccount(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "Add new account");

	int	 ret = 0;
	char	*email = NULL;
	char	*password = NULL;
	char	*apikey = NULL;
	char 	*resp_str = NULL;
	json_t	*resp = NULL;
	json_t	*js_account = NULL;

	if ((js_account = json_object_get(jmsg, "account")) == NULL)
		return;

	json_unpack(js_account, "{s:s}", "email", &email);
	json_unpack(js_account, "{s:s}", "password", &password);

	if (email == NULL || password == NULL) {
		jlog(L_ERROR, "Invalid message\n");
		return;
	}

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	apikey = pki_gen_apikey();
	if (apikey == NULL) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	ret = dao_add_client(email, password, apikey);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("duplicate"));
		goto out;
	}

	json_object_set_new(resp, "response", json_string("success"));
	json_object_set_new(resp, "apikey", json_string(apikey));

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(apikey);
	return;
}

void
getAccountApiKey(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "get account api key");

	int	 ret = 0;
	char	*email = NULL;
	char	*password = NULL;
	char	*apikey = NULL;
	char	*resp_str = NULL;
	json_t	*resp = NULL;
	json_t	*js_account = NULL;

	if ((js_account = json_object_get(jmsg, "account")) == NULL)
		return;

	json_unpack(js_account, "{s:s}", "email", &email);
	json_unpack(js_account, "{s:s}", "password", &password);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_account_apikey(&apikey, email, password);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		jlog(L_DEBUG, "dao_fetch_account_apikey failed");
		goto out;
	}

	if (apikey == NULL) {
		json_object_set_new(resp, "response", json_string("denied"));
		jlog(L_DEBUG, "apikey is NULL");
		goto out;
	}

	json_object_set_new(resp, "response", json_string("success"));
	json_object_set_new(resp, "apikey", json_string(apikey));

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(apikey);

	return;
}

int
CB_fetch_network_by_client_id_desc(void *msg,
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

void
addNetwork(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "add network");

	int		 ret = 0;
	char		*client_id = NULL;
	char		*apikey = NULL;
	char		*name = NULL;
	char		*resp_str = NULL;
	json_t		*resp = NULL;
	json_t		*js_network = NULL;

	int		exp_delay;
	char		*emb_cert_ptr = NULL;
	long		size;
	char		*emb_pvkey_ptr = NULL;
	char		*serv_cert_ptr;
	char		*serv_pvkey_ptr;
	char		emb_serial[10];
	struct		ippool *ippool = NULL;
	size_t		pool_size;
	passport_t	*nvswitch_passport = NULL;
	digital_id_t	*server_id = NULL;
	embassy_t	*emb = NULL;
	digital_id_t	*embassy_id = NULL;

	if ((js_network = json_object_get(jmsg, "network")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_network, "{s:s}", "name", &name);

	/* check apikey and name... */

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}
	if (client_id == NULL) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}

	/* 3.1- Initialise embassy */
	exp_delay = pki_expiration_delay(10);

	embassy_id = pki_digital_id("embassy", "CA", "Quebec", "", "admin@netvirt.org", "NetVirt");

	emb = pki_embassy_new(embassy_id, exp_delay);

	pki_write_certificate_in_mem(emb->certificate, &emb_cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &emb_pvkey_ptr, &size);

	/* 3.2- Initialize server passport */

	server_id = pki_digital_id("nvswitch", "CA", "Quebec", "", "admin@netvirt.org", "NetVirt");

	nvswitch_passport = pki_embassy_deliver_passport(emb, server_id, exp_delay);

	pki_write_certificate_in_mem(nvswitch_passport->certificate, &serv_cert_ptr, &size);
	pki_write_privatekey_in_mem(nvswitch_passport->keyring, &serv_pvkey_ptr, &size);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);

	/* Create an IP pool */
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);

	ret = dao_add_context(client_id,
				name,
				"44.128.0.0/16",
				emb_cert_ptr,
				emb_pvkey_ptr,
				emb_serial,
				serv_cert_ptr,
				serv_pvkey_ptr,
				ippool->pool,
				pool_size);

	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	if (ret == -2) {
		json_object_set_new(resp, "response", json_string("duplicate"));
		goto out;
	}

	/* send context update to nvswitch */
	DNDSMessage_t *msg_up;
	DNDSMessage_new(&msg_up);
	DNDSMessage_set_channel(msg_up, 0);
	DNDSMessage_set_pdu(msg_up, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg_up, 0);
	DSMessage_set_ackNumber(msg_up, 1);
	DSMessage_set_action(msg_up, action_addNetwork);
	DSMessage_set_operation(msg_up, dsop_PR_searchResponse);

	dao_fetch_network_by_client_id_desc(client_id, name, msg_up,
		CB_fetch_network_by_client_id_desc);

	SearchResponse_set_searchType(msg_up, SearchType_all);
	SearchResponse_set_result(msg_up, DNDSResult_success);

	if (g_switch_netc) {
		net_send_msg(g_switch_netc, msg_up);
	}
	DNDSMessage_del(msg_up);
	/* */

	json_object_set_new(resp, "response", json_string("success"));
out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	pki_free_digital_id(embassy_id);
	pki_free_digital_id(server_id);
	pki_passport_free(nvswitch_passport);
	pki_embassy_free(emb);
	ippool_free(ippool);

	free(serv_cert_ptr);
	free(serv_pvkey_ptr);
	free(emb_cert_ptr);
	free(emb_pvkey_ptr);
	free(client_id);
	free(resp_str);

	json_decref(resp);
}

int
CB_listNetwork(void *arg, char *name)
{
	json_t	*array;
	json_t	*network;

	array = (json_t*)arg;
	network = json_object();

	json_object_set_new(network, "name", json_string(name));
	json_array_append_new(array, network);

	return 0;
}

void
listNetwork(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "list network");

	int	 ret = 0;
	char	*client_id = NULL;
	char	*apikey = NULL;
	char	*resp_str = NULL;
	json_t	*array;
	json_t	*resp = NULL;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);

	/* XXX check apikey ... */

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (client_id == NULL) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	array = json_array();
	ret = dao_fetch_networks_by_client_id(client_id, array, CB_listNetwork);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	json_object_set_new(resp, "networks", array);
	json_object_set_new(resp, "response", json_string("success"));

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);

	return;
}

int
CB_listNode(void *ptr, char *uuid, char *description, char *provcode, char *ipaddress, char *status)
{
	json_t	*array;
	json_t	*node;

	array = (json_t*)ptr;
	node = json_object();

	json_object_set_new(node, "status", json_string(status));
	json_object_set_new(node, "ipaddress", json_string(ipaddress));
	json_object_set_new(node, "provcode", json_string(provcode));
	json_object_set_new(node, "description", json_string(description));
	json_object_set_new(node, "uuid", json_string(uuid));

	json_array_append_new(array, node);

	return 0;
}

void
listNode(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "list node");

	int	 ret = 0;
	char	*client_id = NULL;
	char	*context_id = NULL;
	char	*apikey = NULL;
	char	*context_name = NULL;
	char	*resp_str = NULL;
	json_t	*js_network = NULL;
	json_t	*array = NULL;
	json_t	*resp = NULL;

	if ((js_network = json_object_get(jmsg, "network")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_network, "{s:s}", "name", &context_name);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (client_id == NULL) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}

	ret = dao_fetch_network_id(&context_id, client_id, context_name);
	if (context_id == NULL) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}

	array = json_array();
	ret = dao_fetch_node_from_context_id(context_id, array, CB_listNode);
	if (ret != 0) {
		jlog(L_WARNING, "dao fetch node from context id failed: %s", context_id);
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}
	json_object_set_new(resp, "nodes", array);
	json_object_set_new(resp, "response", json_string("success"));

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);
	free(context_id);

	return;
}
