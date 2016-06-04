/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
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
update_node_status(struct session_info **sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "update-node-status");

	char	*status;
	char	*local_ipaddr = NULL;
	char	*uuid = NULL;
	char	*network_uuid = NULL;
	char	*ptr = NULL;

	json_t	*node;


	node = json_object_get(jmsg, "node");
	json_unpack(node, "{s:s}", "status", &status);
	json_unpack(node, "{s:s}", "local-ipaddr", &local_ipaddr);
	json_unpack(node, "{s:s}", "uuid", &uuid);
	json_unpack(node, "{s:s}", "networkuuid", &network_uuid);

	dao_update_node_status(network_uuid, uuid, status, local_ipaddr);

	json_decref(node);

	return;
}

void
del_network(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "del-network");

	int		ret = 0;
	char		*client_id = NULL;
	char		*apikey = NULL;
	char		*network_uuid = NULL;
	char		*fwd_str = NULL;
	char		*resp_str = NULL;
	json_t		*resp = NULL;
	json_t		*js_network = NULL;

	if ((js_network = json_object_get(jmsg, "network")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_network, "{s:s}", "uuid", &network_uuid);

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
/*
	ret = dao_fetch_network_id(&network_id, client_id, network_uuid);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}
	if (network_id == NULL) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}
*/
	jlog(L_NOTICE, "deleting nodes belonging to context: %s", network_uuid);
	ret = dao_del_node_by_context_id(network_uuid);
	if (ret < 0) {
		jlog(L_NOTICE, "deleting nodes failed!");
		return;
	}

	jlog(L_NOTICE, "deleting context: %s", network_uuid);
	ret = dao_del_context(client_id, network_uuid);
	if (ret < 0) {
		/* FIXME: multiple DAO calls should be commited to the DB once
		 * all calls have succeeded.
		 */
		jlog(L_NOTICE, "deleting context failed!");
		return;
	}

	/* Forward del-network to the switch */
	if (switch_sinfo != NULL) {
		json_object_del(jmsg, "apikey");
		json_object_set_new(js_network, "networkuuid", json_string(network_uuid));
		json_object_del(js_network, "uuid");
		json_object_del(js_network, "name");

		fwd_str = json_dumps(jmsg, 0);
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, fwd_str, strlen(fwd_str));
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));
		free(fwd_str);
	}
	/* * */
out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);
}

void
add_node(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "add-node");

	int		 ret = 0;
	char		*network_uuid = NULL;
	char		*client_id = NULL;
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
	char		 common_name[64] = {0};
	char		 alt_name[256] = {0};
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

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_node, "{s:s}", "networkuuid", &network_uuid);
	json_unpack(js_node, "{s:s}", "description", &description);

	if (apikey == NULL ||
	    network_uuid == NULL ||
	    description == NULL) {

		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}
/*
	ret = dao_fetch_network_id(&context_id, client_id, network_uuid);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}
*/
	exp_delay = pki_expiration_delay(10);
	ret = dao_fetch_context_embassy(network_uuid, &emb_cert_ptr, &emb_pvkey_ptr, &serial, &ippool_bin);
	jlog(L_DEBUG, "serial: %s", serial);
	if (ret != 0) {
		jlog(L_ERROR, "failed to fetch context embassy");
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	emb = pki_embassy_load_from_memory(emb_cert_ptr, emb_pvkey_ptr, atoi(serial));

	uuid = uuid_v4();
	provcode = uuid_v4();

	snprintf(common_name, sizeof(common_name), "nva2-%s", network_uuid);
	jlog(L_DEBUG, "common_name: %s", common_name);

	snprintf(alt_name, sizeof(alt_name), "URI:%s@%s", uuid, network_uuid);
	jlog(L_DEBUG, "alt_name: %s", alt_name);

	digital_id_t *node_ident = NULL;
	node_ident = pki_digital_id(common_name, alt_name, "", "", "admin@netvirt.org", "NetVirt");

	passport_t *node_passport = NULL;
	node_passport = pki_embassy_deliver_passport(emb, node_ident, exp_delay);

	/* FIXME verify is the value is freed or not via BIO_free() */
	pki_write_certificate_in_mem(node_passport->certificate, &node_cert_ptr, &size);
	pki_write_privatekey_in_mem(node_passport->keyring, &node_pvkey_ptr, &size);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);
	printf("serial: %s\n", emb_serial);
	ret = dao_update_embassy_serial(network_uuid, emb_serial);
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

	ret = dao_add_node(network_uuid, uuid, node_cert_ptr, node_pvkey_ptr, provcode, description, ip);
	if (ret == -1) {
		jlog(L_ERROR, "failed to add node");
		json_object_set_new(resp, "response", json_string("error"));
		goto free2;
	}

	ret = dao_update_context_ippool(network_uuid, ippool->pool, pool_size);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy ippool");
		json_object_set_new(resp, "response", json_string("error"));
		goto free2;
	}

	/* forward new node to nvswitch */
	char	*fwd_resp_str = NULL;
	json_t	*array = NULL;
	json_t	*node = NULL;
	json_t	*fwd_resp = NULL;

	if (switch_sinfo != NULL) {
		fwd_resp = json_object();
		node = json_object();
		array = json_array();

		json_object_set_new(fwd_resp, "action", json_string("listall-node"));
		json_object_set_new(fwd_resp, "response", json_string("more-data"));

		json_object_set_new(node, "networkuuid", json_string(network_uuid));
		json_object_set_new(node, "uuid", json_string(uuid));

		json_array_append_new(array, node);
		json_object_set_new(fwd_resp, "nodes", array);

		fwd_resp_str = json_dumps(fwd_resp, 0);

		if (switch_sinfo && switch_sinfo->bev)
			bufferevent_write(switch_sinfo->bev, fwd_resp_str, strlen(fwd_resp_str));
		if (switch_sinfo && switch_sinfo->bev)
			bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));

		json_decref(fwd_resp);
		free(fwd_resp_str);
	}

	/* * */

	json_object_set_new(resp, "response", json_string("success"));

free2:
	ippool_free(ippool);

free1:
	pki_passport_free(node_passport);
	pki_embassy_free(emb);
	pki_free_digital_id(node_ident);

	free(client_id);


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
del_node(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "del-node");

	int		ret = 0;
	char		*client_id = NULL;
	char		*network_uuid = NULL;
	char		*node_uuid = NULL;
	char		*apikey = NULL;
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
	json_unpack(js_node, "{s:s}", "networkuuid", &network_uuid);
	json_unpack(js_node, "{s:s}", "uuid", &node_uuid);

	/* check network_uuid and node_uuid */
	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}
/*
	ret = dao_fetch_network_id(&network_id, client_id, network_uuid);
	if (ret != 0) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}
*/
	ret = dao_fetch_node_ip(network_uuid, node_uuid, &ipaddr);
	if (ret != 0) {
		jlog(L_ERROR, "failed to fetch node ip");
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}

	jlog(L_NOTICE, "revoking node: %s, ip:%s, network:%s", node_uuid, ipaddr, network_uuid);
	ret = dao_del_node(network_uuid, node_uuid);
	if (ret != 0) {
		jlog(L_ERROR, "failed to del node");
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	unsigned char *ippool_bin = NULL;
	ret = dao_fetch_context_ippool(network_uuid, &ippool_bin);
	if (ret == -1) {
		jlog(L_ERROR, "failed to fetch context ippool");
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	/* update ip pool */
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ippool_release_ip(ippool, ipaddr);

	ret = dao_update_context_ippool(network_uuid, ippool->pool, pool_size);
	if (ret == -1) {
		jlog(L_ERROR, "failed to update embassy ippool");
	}

	/* Forward del-node to the switch */
	if (switch_sinfo != NULL) {
		json_object_del(jmsg, "apikey");

		fwd_str = json_dumps(jmsg, 0);
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, fwd_str, strlen(fwd_str));
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));
		free(fwd_str);
	}
	/* * */

out:
	resp_str = json_dumps(resp, 0);

	bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);
	free(ipaddr);
	ippool_free(ippool);
}

void
provisioning(struct session_info **sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "provisioning");

	char	*cert = NULL;
	char	*pkey = NULL;
	char	*tcert = NULL;
	char	*ipaddr = NULL;

	char	*provcode;
	char	*tid;
	char	*resp_str = NULL;
	json_t	*node;
	json_t	*resp = NULL;

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

	bufferevent_write((*sinfo)->bev, resp_str, strlen(resp_str));
	bufferevent_write((*sinfo)->bev, "\n", strlen("\n"));

	free(cert);
	free(pkey);
	free(tcert);
	free(ipaddr);
	free(resp_str);
	json_decref(resp);

	return;
}

static int
CB_listall_network(void *arg, int remaining,
				char *id,
				char *uuid,
				char *description,
				char *client_id,
				char *subnet,
				char *netmask,
				char *cert,
				char *pkey,
				char *tcert)
{
	char			*resp_str = NULL;
	struct session_info	**sinfo;
	json_t			*array;
	json_t			*network;
	json_t			*resp = NULL;

	sinfo = arg;
	network = json_object();
	array = json_array();
	resp = json_object();

	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("listall-network"));

	json_object_set_new(network, "id", json_string(id));
	json_object_set_new(network, "uuid", json_string(uuid));
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

	if ((resp_str = json_dumps(resp, 0)) == NULL)
		goto out;

	if (*sinfo == NULL || (*sinfo)->bev == NULL)
		goto out;
	bufferevent_write((*sinfo)->bev, resp_str, strlen(resp_str));

	if (*sinfo == NULL || (*sinfo)->bev == NULL)
		goto out;
	bufferevent_write((*sinfo)->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	return 0;
out:
	json_decref(resp);
	free(resp_str);
	return -1;
}

void
listall_network(struct session_info **sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "listallNetwork");

	char	*resp_str = NULL;
	json_t	*resp = NULL;

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("listall-network"));

	if (dao_fetch_context(sinfo, CB_listall_network) == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	json_decref(resp);
	return;
out:
	resp_str = json_dumps(resp, 0);
	if (*sinfo && (*sinfo)->bev != NULL)
		bufferevent_write((*sinfo)->bev, resp_str, strlen(resp_str));
	if (*sinfo && (*sinfo)->bev != NULL)
		bufferevent_write((*sinfo)->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);

	return;
}

static int
CB_listall_node(void *arg, int remaining, char *network_uuid, char *uuid)
{
	char			*resp_str = NULL;
	struct	session_info	**sinfo;
	json_t			*array;
	json_t			*node;
	json_t			*resp = NULL;

	sinfo = arg;
	node = json_object();
	array = json_array();
	resp = json_object();

	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("listall-node"));

	json_object_set_new(node, "networkuuid", json_string(network_uuid));
	json_object_set_new(node, "uuid", json_string(uuid));

	json_array_append_new(array, node);

	json_object_set_new(resp, "nodes", array);
	if (remaining > 0)
		json_object_set_new(resp, "response", json_string("more-data"));
	else
		json_object_set_new(resp, "response", json_string("success"));

	resp_str = json_dumps(resp, 0);

	if (*sinfo == NULL || (*sinfo)->bev == NULL)
		goto out;
	bufferevent_write((*sinfo)->bev, resp_str, strlen(resp_str));

	if (*sinfo == NULL || (*sinfo)->bev == NULL)
		goto out;
	bufferevent_write((*sinfo)->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	return 0;
out:
	json_decref(resp);
	free(resp_str);
	return -1;
}

void
listall_node(struct session_info **sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "listallNode");

	char	*resp_str = NULL;
	json_t	*resp = NULL;

	if (dao_fetch_node_uuid_networkuuid(sinfo, CB_listall_node) == 0)
		return;

	resp = json_object();
	json_object_set_new(resp, "response", json_string("error"));
	json_object_set_new(resp, "action", json_string("listall-node"));

	resp_str = json_dumps(resp, 0);

	if (*sinfo && (*sinfo)->bev != NULL)
		bufferevent_write((*sinfo)->bev, resp_str, strlen(resp_str));
	if (*sinfo && (*sinfo)->bev != NULL)
		bufferevent_write((*sinfo)->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);

	return;

}

void
activate_account(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "activate account");

	int	ret = 0;
	char	*apikey = NULL;
	char	*new_apikey = NULL;
	char	*resp_str = NULL;
	json_t	*resp = NULL;
	json_t	*js_account = NULL;

	if ((js_account = json_object_get(jmsg, "account")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	new_apikey = pki_gen_apikey();
	if (apikey == NULL) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	ret = dao_activate_client(apikey);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}

	// XXX check this update ?
	dao_update_client_apikey(apikey, new_apikey);

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
add_account(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "add-account");

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
get_account_apikey(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "get-account-apikey");

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

void
add_network(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "add network");

	int		 ret = 0;
	char		*network_uuid = NULL;
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
	char		*serv_cert_ptr = NULL;
	char		*serv_pvkey_ptr = NULL;
	char		emb_serial[10];
	struct		ippool *ippool = NULL;
	size_t		pool_size;
	passport_t	*nvswitch_passport = NULL;
	digital_id_t	*server_id = NULL;
	embassy_t	*emb = NULL;
	digital_id_t	*embassy_id = NULL;

	if ((js_network = json_object_get(jmsg, "network")) == NULL)
		return;

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_network, "{s:s}", "name", &name);

	if (apikey == NULL ||
	    name == NULL) {

		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

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

	ret = dao_add_vnetwork(&network_uuid, client_id,
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

	/* forward new network to nvswitch */
//	char	*netid = NULL;
	char	*fwd_resp_str = NULL;
	json_t	*array;
	json_t	*network;
	json_t	*fwd_resp = NULL;

	if (switch_sinfo != NULL) {
//		dao_fetch_network_id(&netid, client_id, name);

		network = json_object();
		array = json_array();
		fwd_resp = json_object();

		json_object_set_new(fwd_resp, "action", json_string("listall-network"));
		json_object_set_new(fwd_resp, "response", json_string("more-data"));

		json_object_set_new(network, "uuid", json_string(network_uuid));
		json_object_set_new(network, "network", json_string("44.128.0.0"));
		json_object_set_new(network, "netmask", json_string("255.255.0.0"));
		json_object_set_new(network, "cert", json_string(serv_cert_ptr));
		json_object_set_new(network, "pkey", json_string(serv_pvkey_ptr));
		json_object_set_new(network, "tcert", json_string(emb_cert_ptr));

		json_array_append_new(array, network);
		json_object_set_new(fwd_resp, "networks", array);

		fwd_resp_str = json_dumps(fwd_resp, 0);

		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, fwd_resp_str, strlen(fwd_resp_str));
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));

		json_decref(fwd_resp);
		free(fwd_resp_str);
	}
	/* * */

	json_object_set_new(resp, "response", json_string("success"));
out:
	resp_str = json_dumps(resp, 0);

	if (sinfo->bev != NULL)
		bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	if (sinfo->bev != NULL)
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

static int
CB_list_network(void *arg, char *name, char *uuid)
{
	json_t	*array;
	json_t	*network;

	array = (json_t*)arg;
	network = json_object();

	json_object_set_new(network, "name", json_string(name));
	json_object_set_new(network, "uuid", json_string(uuid));
	json_array_append_new(array, network);

	return 0;
}

void
list_network(struct session_info *sinfo, json_t *jmsg)
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
	ret = dao_fetch_networks_by_client_id(client_id, array, CB_list_network);
	if (ret == -1) {
		json_object_set_new(resp, "response", json_string("error"));
		goto out;
	}

	json_object_set_new(resp, "networks", array);
	json_object_set_new(resp, "response", json_string("success"));

out:
	resp_str = json_dumps(resp, 0);

	if (sinfo->bev != NULL)
		bufferevent_write(sinfo->bev, resp_str, strlen(resp_str));
	if (sinfo->bev != NULL)
		bufferevent_write(sinfo->bev, "\n", strlen("\n"));

	json_decref(resp);
	free(resp_str);
	free(client_id);

	return;
}

static int
CB_list_node(void *ptr, char *uuid, char *description, char *provcode, char *ipaddress, char *status)
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
list_node(struct session_info *sinfo, json_t *jmsg)
{
	jlog(L_DEBUG, "list-node");

	int	 ret = 0;
	char	*client_id = NULL;
	char	*apikey = NULL;
	char	*network_uuid = NULL;
	char	*resp_str = NULL;
	json_t	*js_network = NULL;
	json_t	*array = NULL;
	json_t	*resp = NULL;

	if ((js_network = json_object_get(jmsg, "network")) == NULL)
		return;

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	json_unpack(js_network, "{s:s}", "uuid", &network_uuid);

	resp = json_object();
	json_object_set_new(resp, "tid", json_string("tid"));
	json_object_set_new(resp, "action", json_string("response"));

	ret = dao_fetch_client_id_by_apikey(&client_id, apikey);
	if (client_id == NULL) {
		json_object_set_new(resp, "response", json_string("denied"));
		goto out;
	}
/*
	ret = dao_fetch_network_id(&context_id, client_id, network_uuid);
	if (context_id == NULL) {
		json_object_set_new(resp, "response", json_string("no-such-object"));
		goto out;
	}
*/
	array = json_array();
	ret = dao_fetch_node_from_context_id(network_uuid, array, CB_list_node);
	if (ret != 0) {
		jlog(L_WARNING, "dao fetch node from context id failed: %s", network_uuid);
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

	return;
}
