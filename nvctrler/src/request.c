/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <sys/queue.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <event2/util.h>
#include <jansson.h>

#include <log.h>
#include <pki.h>

#include "controller.h"
#include "dao.h"
#include "ippool.h"
#include "request.h"

extern struct session_info *switch_sinfo;

void
buf_free_cb(const void *data, size_t datalen, void *extra)
{
	free((void *)data);
}

void
req_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*output_headers = NULL;

	evhttp_connection_free(arg);
	output_headers = evhttp_request_get_output_headers(req);
	evhttp_clear_headers(output_headers);

	return;
}

int
client_create(char *msg)
{
	struct evhttp_connection	*evhttp_conn = NULL;
	struct evhttp_request		*req;
	struct evkeyvalq		*output_headers = NULL;
	json_t				*jmsg = NULL;
	json_error_t			 error;
	int				 ret;
	char				*email;
	char				*email_encoded = NULL;
	char				*password;
	char				*apikey = NULL;
	char				*emailquery = NULL;

	ret = -1;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s, s:s}", "email", &email,
	    "password", &password) < 0) {
		log_warnx("%s: json_unpack\n", __func__);
		goto cleanup;
	}

	if ((apikey = pki_gen_key()) == NULL) {
		log_warnx("%s: pki_gen_key", __func__);
		goto cleanup;
	}

	if (dao_client_create(email, password, apikey) < 0) {
		log_warnx("%s: dao_client_create(%s)", __func__, email);
		goto cleanup;
	}

	evhttp_conn = evhttp_connection_base_new(ev_base, NULL, "localhost", 8000);
	req = evhttp_request_new(req_cb, evhttp_conn);

	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Content-Type", "text/plain");
	evhttp_add_header(output_headers, "Host", "*");

	if ((email_encoded = evhttp_encode_uri(email)) == NULL) {
		log_warnx("%s: email_encoded", __func__);
		goto cleanup;
	}

	asprintf(&emailquery, "/email?msgtype=welcome&key=%s&to=\"%s\"",
	    apikey, email_encoded);

	evhttp_make_request(evhttp_conn, req, EVHTTP_REQ_GET, emailquery);

	// XXX debug purpose
	FILE    *tmp;
	tmp = fopen("/tmp/apikey", "w");
	fprintf(tmp, "%s", apikey);
	fclose(tmp);

	ret = 0;

cleanup:
	json_decref(jmsg);

	free(apikey);
	free(emailquery);
	free(email_encoded);
	return (ret);
}

int
client_activate(char *msg)
{
	json_t		*jmsg;
	json_error_t	 error;
	int		 ret;
	char		*apikey = NULL;
	char		*new_apikey = NULL;

	ret = -1;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s}", "apikey", &apikey) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}

	if ((new_apikey = pki_gen_key()) == NULL) {
		log_warnx("%s: pki_gen_key", __func__);
		goto cleanup;
	}

	if (dao_client_activate(apikey) == -1) {
		log_warnx("%s: dao_client_activate", __func__);
		goto cleanup;
	}

	if (dao_client_update_apikey(apikey, new_apikey) < 0) {
		log_warnx("%s: dao_client_update", __func__);
		goto cleanup;
	}

	ret = 0;

cleanup:
	json_decref(jmsg);
	free(new_apikey);
	return (ret);
	
}

int
client_get_newapikey(char *msg, char **resp)
{
	json_t		*jmsg = NULL;
	json_t		*jresp = NULL;
	json_t		*jclient;
	json_error_t	 error;
	int		 ret;
	char		*email;
	char		*password;
	char		*new_apikey = NULL;

	ret = -1;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s, s:s}", "email", &email,
	    "password", &password) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}

	if ((new_apikey = pki_gen_key()) == NULL) {
		log_warnx("%s: new_apikey", __func__);
		goto cleanup;
	}

	if (dao_client_update_apikey2(email, password, new_apikey) < 0) {
		log_warnx("%s: dao_client_update_apikey2", __func__);
		goto cleanup;
	}

	if ((jresp = json_object()) == NULL ||
	    (jclient = json_object()) == NULL ||
	    json_object_set_new(jresp, "client", jclient) < 0 ||
	    json_object_set_new(jclient, "apikey",
	    json_string_nocheck(new_apikey)) < 0 ||
	    (*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		log_warnx("%s: json_dumps", __func__);
			goto cleanup;
	}

	ret = 0;

cleanup:
	json_decref(jmsg);
	json_decref(jresp);
	free(new_apikey);

	return (ret);
}

int
client_get_newresetkey(char *msg, char **resp)
{
	struct evhttp_connection	*evhttp_conn;
	struct evhttp_request		*req;
	struct evkeyvalq		*output_headers;
	json_t				*jmsg = NULL;
	json_t				*jclient;
	json_t				*jresp = NULL;
	json_error_t			 error;
	int				 ret;
	char				*email;
	char				*resetkey = NULL;
	char				*emailquery = NULL;
	char				*email_encoded = NULL;

	ret = -1;
	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s}", "email", &email) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}

	if ((resetkey = pki_gen_key()) == NULL) {
		log_warnx("%s: pki_gen_key", __func__);
		goto cleanup;
	}

	if (dao_client_update_resetkey(email, resetkey) < 0) {
		log_warnx("%s: dao_client_udpate", __func__);
		goto cleanup;
	}

	if ((jresp = json_object()) == NULL ||
	    (jclient = json_object()) == NULL ||
	    json_object_set_new(jresp, "client", jclient) < 0 ||
	    json_object_set_new(jclient, "resetkey",
	    json_string(resetkey)) < 0 ||
	    (*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto cleanup;
	}

	evhttp_conn = evhttp_connection_base_new(ev_base, NULL, "localhost", 8000);
	req = evhttp_request_new(req_cb, evhttp_conn);

	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Content-Type", "text/plain");
	evhttp_add_header(output_headers, "Host", "*");

	if ((email_encoded = evhttp_encode_uri(email)) == NULL) {
		log_warnx("%s: email_encoded", __func__);
		goto cleanup;
	}

	asprintf(&emailquery, "/email?msgtype=reset&key=%s&to=\"%s\"",
	    resetkey, email_encoded);

	evhttp_make_request(evhttp_conn, req, EVHTTP_REQ_GET, emailquery);

	// XXX debug purpose
	FILE    *tmp;
	tmp = fopen("/tmp/resetkey", "w");
	fprintf(tmp, "%s", resetkey);
	fclose(tmp);

	ret = 0;

cleanup:
	json_decref(jmsg);
	json_decref(jresp);

	free(resetkey);
	free(emailquery);
	free(email_encoded);

	return (ret);
}

int
client_reset_password(char *msg)
{
	json_t		*jmsg = NULL;
	json_error_t	 error;
	char		*email;
	char		*resetkey;
	char		*newpassword;
	int		 ret;

	ret = -1;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s, s:s, s:s}",
	    "email", &email, "resetkey", &resetkey,
	    "newpassword", &newpassword) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}

	if (dao_client_update_password(email, resetkey, newpassword) < 0) {
		log_warnx("%s: dao_client_update_password", __func__);
		goto cleanup;
	}

	ret = 0;

cleanup:
	json_decref(jmsg);	
	return (ret);
}

int
network_create(char *msg, const char *apikey)
{
	passport_t	*nvswitch_passport = NULL;
	digital_id_t	*server_id = NULL;
	embassy_t	*emb = NULL;
	digital_id_t	*embassy_id = NULL;
	json_t		*jmsg = NULL;
	json_error_t	 error;
	struct ippool	*ippool = NULL;
	long		 size;
	int		 ret = 0;
	int		 exp_delay;
	size_t		 pool_size;
	char		*network_uid = NULL;
	char		*client_id = NULL;
	char		*description = NULL;
	char		*subnet;
	char		*netmask;
	char		*emb_cert_ptr = NULL;
	char		*emb_pvkey_ptr = NULL;
	char		*serv_cert_ptr = NULL;
	char		*serv_pvkey_ptr = NULL;
	char		 emb_serial[10];

	ret = -1;

	if (dao_client_get_id(&client_id, apikey) < 0) {
		log_warnx("%s: dao_client_get_id", __func__);
		goto cleanup;
	}

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("json_loadb: %s", error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s, s:s, s:s}", "description", &description,
	    "subnet", &subnet, "netmask", &netmask) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}

	/* initialize embassy */
	exp_delay = pki_expiration_delay(10);

	// XXX remove the needs of the embassy_id
	embassy_id = pki_digital_id("embassy", "CA", "Quebec", "", "admin@netvirt.org", "NetVirt");

	emb = pki_embassy_new(embassy_id, exp_delay);

	pki_write_certificate_in_mem(emb->certificate, &emb_cert_ptr, &size);
	pki_write_privatekey_in_mem(emb->keyring, &emb_pvkey_ptr, &size);

	/* initialize server passport */

	server_id = pki_digital_id("nvswitch", "CA", "Quebec", "", "admin@netvirt.org", "NetVirt");

	nvswitch_passport = pki_embassy_deliver_passport(emb, server_id, exp_delay);

	pki_write_certificate_in_mem(nvswitch_passport->certificate, &serv_cert_ptr, &size);
	pki_write_privatekey_in_mem(nvswitch_passport->keyring, &serv_pvkey_ptr, &size);

	snprintf(emb_serial, sizeof(emb_serial), "%d", emb->serial);

	/* create an IP pool */
	ippool = ippool_new(subnet, netmask);
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);

	network_uid = pki_gen_uid();
	ret = dao_network_create(client_id,
				network_uid,
				description,
				subnet,
				netmask,
				emb_cert_ptr,
				emb_pvkey_ptr,
				emb_serial,
				serv_cert_ptr,
				serv_pvkey_ptr,
				ippool->pool,
				pool_size);

	/* forward new network to nvswitch */
	char	*fwd_resp_str = NULL;
	json_t	*array;
	json_t	*network;
	json_t	*fwd_resp = NULL;

	if (switch_sinfo != NULL) {

		network = json_object();
		array = json_array();
		fwd_resp = json_object();

		json_object_set_new(fwd_resp, "action", json_string("switch-network-list"));
		json_object_set_new(fwd_resp, "response", json_string("more-data"));

		json_object_set_new(network, "uid", json_string(network_uid));
		json_object_set_new(network, "cert", json_string(serv_cert_ptr));
		json_object_set_new(network, "pvkey", json_string(serv_pvkey_ptr));
		json_object_set_new(network, "cacert", json_string(emb_cert_ptr));

		json_array_append_new(array, network);
		json_object_set_new(fwd_resp, "networks", array);

		fwd_resp_str = json_dumps(fwd_resp, 0);

		// XXX use buffer
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, fwd_resp_str, strlen(fwd_resp_str));
		if (switch_sinfo != NULL && switch_sinfo->bev != NULL)
			bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));

		json_decref(fwd_resp);
		free(fwd_resp_str);
	}
	/* * */

	agent_control_network_create(network_uid, serv_cert_ptr, serv_pvkey_ptr, emb_cert_ptr);

cleanup:

	json_decref(jmsg);
	pki_free_digital_id(embassy_id);
	pki_free_digital_id(server_id);
	pki_passport_free(nvswitch_passport);
	pki_embassy_free(emb);
	ippool_free(ippool);

	free(network_uid);
	free(serv_cert_ptr);
	free(serv_pvkey_ptr);
	free(emb_cert_ptr);
	free(emb_pvkey_ptr);
	free(client_id);

	return (ret);
}

int
network_list_cb(const char *uid, const char *description, void *arg)
{
	json_t	*array;
	json_t	*network;

	array = arg;
	network = json_object();

	json_object_set_new(network, "uid", json_string(uid));
	json_object_set_new(network, "description", json_string(description));
	json_array_append_new(array, network);

	return (0);
}

int
network_list(const char *apikey, char **resp)
{
	json_t	*array;
	json_t	*jresp = NULL;
	int	 ret;

	ret = -1;

	if ((array = json_array()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto cleanup;
	}

	if (dao_network_list(apikey, network_list_cb, array) < 0) {
		log_warnx("%s: dao_network_list", __func__);
		goto cleanup;
	}

	if ((jresp = json_object()) == NULL ||
	    json_object_set_new(jresp, "networks", array) < 0 ||
	    (*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		goto cleanup;
	}

	ret = 0;

cleanup:
	json_decref(jresp);

	return (ret);
}

// XXX store it in DB
int
regions_list(const char *apikey, char **resp)
{
	json_t	*array;
	json_t	*region;
	json_t	*jresp = NULL;
	int	 ret = -1;

	if ((array = json_array()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto cleanup;
	}

	// TODO hardcoded for now
	if ((region = json_object()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto cleanup;
	}
	json_object_set_new(region, "name", json_string("Toronto 1"));
	json_object_set_new(region, "tag", json_string("TORONTO1"));
	json_array_append_new(array, region);

/*
	if ((region = json_object()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto cleanup;
	}
	json_object_set_new(region, "name", json_string("London 1"));
	json_object_set_new(region, "tag", json_string("LN1"));
	json_array_append_new(array, region);
*/

	if ((jresp = json_object()) == NULL ||
	    json_object_set_new(jresp, "regions", array) < 0 ||
	   (*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		goto cleanup;
	}

	ret = 0;

cleanup:
	json_decref(jresp);

	return (ret);
}

int
network_delete(const char *description, const char *apikey)
{
	int	 ret;
	char	*network_uid = NULL;

	ret = -1;

	if (dao_network_delete(&network_uid, description, apikey) < 0) {
		log_warnx("%s: dao_network", __func__);
		goto cleanup;
	}

	switch_network_delete(network_uid);
	agent_control_network_delete(network_uid);

	ret = 0;

cleanup:
	free(network_uid);
	return (ret);
}

int
node_create(const char *msg, const char *apikey)
{
	json_t		*jmsg = NULL;
	json_error_t	 error;
	struct ippool	*ippool = NULL;
	int		 ret = 0;
	int		 pool_size;
	char		*client_id = NULL;
	char		*network_uid = NULL;
	char		*uid = NULL;
	char		*key = NULL;
	char		*network_description = NULL;
	char		*description = NULL;
	char		*ipaddress = NULL;
	char		*subnet = NULL;
	char		*netmask = NULL;
	unsigned char	*tmp_pool = NULL;
	char		 provlink[512];

	ret = -1;

	if (dao_client_get_id(&client_id, apikey) < 0) {
		log_warnx("%s: dao_client_get_id", __func__);
		goto cleanup;
	}

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s, s:s}",
	    "network_description", &network_description,
	    "description", &description) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}


	if (dao_network_get_ippool(network_description, &network_uid,
	    &subnet, &netmask, &tmp_pool) < 0) {
		log_warnx("%s: dao_network_get_ippool", __func__);
		goto cleanup;
	}

	ippool = ippool_new(subnet, netmask);
	free(ippool->pool);
	ippool->pool = (uint8_t*)tmp_pool;
	tmp_pool = NULL;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ipaddress = ippool_get_ip(ippool);

	if ((uid = pki_gen_uid()) == NULL) {
		log_warnx("%s: pki_gen_uid", __func__);
		goto cleanup;
	}

	if ((key = pki_gen_key()) == NULL) {
		log_warnx("%s: pki_gen_key", __func__);
		goto cleanup;
	}

	snprintf(provlink, sizeof(provlink), "nv:?v=2&a=%s&w=%s&n=%s&k=%s",
	    provsrv_addr, network_uid, uid, key);

	if (dao_node_create(network_uid, uid, provlink, description, ipaddress)
	    < 0) {
		log_warnx("%s: dao_node_create", __func__);
		goto cleanup;
	}

	if (dao_network_update_ippool(network_uid, ippool->pool,
	    pool_size) < 0) {
		log_warnx("%s: dao_network_update_ippool", __func__);
		goto cleanup;
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

		json_object_set_new(fwd_resp, "action", json_string("switch-node-list"));
		json_object_set_new(fwd_resp, "response", json_string("more-data"));

		json_object_set_new(node, "network_uid", json_string(network_uid));
		json_object_set_new(node, "uid", json_string(uid));

		json_array_append_new(array, node);
		json_object_set_new(fwd_resp, "nodes", array);

		fwd_resp_str = json_dumps(fwd_resp, 0);

		// XXX use buffer
		if (switch_sinfo && switch_sinfo->bev)
			bufferevent_write(switch_sinfo->bev, fwd_resp_str, strlen(fwd_resp_str));
		if (switch_sinfo && switch_sinfo->bev)
			bufferevent_write(switch_sinfo->bev, "\n", strlen("\n"));

		json_decref(fwd_resp);
		free(fwd_resp_str);
	}
	/* * */

	agent_control_node_create(uid, network_uid, description, ipaddress);

	ret = 0;

cleanup:
	json_decref(jmsg);
	ippool_free(ippool);

	free(network_uid);
	free(subnet);
	free(netmask);
	free(client_id);
	free(uid);
	free(key);

	return (ret);
}

int
node_delete(const char *description, const char *apikey)
{
	int		ret;
	struct ippool	*ippool = NULL;
	size_t		 pool_size;
	uint8_t		*ippool_bin;
	char		*ipaddr = NULL;
	char		*network_uid = NULL;
	char		*subnet = NULL;
	char		*netmask = NULL;
	char		*node_uid = NULL;

	ret = -1;

	if (dao_node_netinfo(description, apikey, &ipaddr, &network_uid,
	    &subnet, &netmask, &ippool_bin) < 0) {
		log_warnx("%s: dao_node_netinfo", __func__);
		goto cleanup;
	}

	/* update ip pool */
	ippool = ippool_new(subnet, netmask);
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ippool_release_ip(ippool, ipaddr);

	if (dao_network_update_ippool(network_uid, ippool->pool,
	    pool_size) < 0) {
		log_warnx("%s: dao_network_update_ippool", __func__);
		goto cleanup;
	}

	if (dao_node_delete(&node_uid, description, apikey) < 0) {
		log_warnx("%s: dao_node_delete", __func__);
		goto cleanup;
	}

	switch_node_delete(node_uid, network_uid);
	agent_control_node_delete(node_uid, network_uid);

	ret = 0;

cleanup:
	free(node_uid);
	free(ipaddr);
	free(network_uid);
	free(subnet);
	free(netmask);
	ippool_free(ippool);
	return (ret);
}

int
node_provisioning(const char *msg, char **resp)
{
	json_t			*jmsg;
	json_t			*jresp;
	json_error_t		 error;
	struct evhttp_uri	*uri = NULL;
	struct evkeyvalq	 headers = TAILQ_HEAD_INITIALIZER(headers);
	int			 ret;
	uint32_t		 serial;
	const char		*errstr;
	const char		*provlink;
	const char		*network_uid;
	const char		*node_uid;
	const char		*node_key;
	const char		*version;
	char			*cn = NULL;
	char			*csr;
	char			*cacert;
	char			*pvkey;
	char			*serial_str;
	char			*node_cert;
	char			 serial_up[10]; // XXX store int serial

	ret = -1;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb: %s", __func__, error.text);
		goto cleanup;
	}

	if (json_unpack(jmsg, "{s:s,s:s}",
	    "csr", &csr, "provlink", &provlink) < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto cleanup;
	}

	if ((uri = evhttp_uri_parse(provlink)) == NULL) {
		log_warnx("%s: evhttp_uri_parse", __func__);
		goto cleanup;
	}

	if ((evhttp_parse_query_str(evhttp_uri_get_query(uri), &headers)) < 0) {
		log_warnx("%s: evhttp_parse_query_str", __func__);
		goto cleanup;
	}

	if (((version = evhttp_find_header(&headers, "v")) == NULL) ||
	    ((network_uid = evhttp_find_header(&headers, "w")) == NULL) ||
	    ((node_uid = evhttp_find_header(&headers, "n")) == NULL) ||
	    ((node_key = evhttp_find_header(&headers, "k")) == NULL)) {
		log_warnx("%s: evhttp_find_headers", __func__);
		goto cleanup;
	}

	/* XXX validate credentials */

	/*
	if (dao_node_delete_provkey(network_uid, node_uid, provlink) < 0) {
		log_warnx("%s: dao_node_delete_provkey", __func__);
		goto cleanup;
	}
	*/

	if (dao_network_get_embassy(network_uid,
	    &cacert, &pvkey, &serial_str) < 0) {
		log_warnx("%s: dao_network_get_embassy", __func__);
		goto cleanup;
	}

	if (asprintf(&cn, "v=2&t=nva&w=%s&n=%s", network_uid, node_uid) < 0) {
		log_warnx("%s: asprintf", __func__);
		goto cleanup;
	}

	serial = (uint32_t)strtonum(serial_str, 1, 4000000, &errstr);
	if (errstr != NULL) {
		log_warnx("%s: strtonum: %s", __func__, errstr);
		goto cleanup;
	}

	if ((node_cert = pki_deliver_cert_from_certreq(csr, cacert, pvkey,
	    serial, cn)) == NULL) {
		log_warnx("%s: pki_deliver_cert_from_certreq", __func__);
		goto cleanup;
	}

	snprintf(serial_up, sizeof(serial_up), "%d", ++serial);
	if (dao_network_update_serial(network_uid, serial_up) < 0) {
		log_warnx("%s: dao_network_update_serial", __func__);
		goto cleanup;
	}

	if ((jresp = json_object()) == NULL ||
	    json_object_set_new_nocheck(jresp, "ctlsrv_addr",
	    json_string(ctlsrv_addr)) < 0 ||
	    json_object_set_new_nocheck(jresp, "cert",
	    json_string(node_cert)) < 0 ||
	    json_object_set_new_nocheck(jresp, "cacert",
	    json_string(cacert)) < 0) {
		log_warnx("%s: json_object", __func__);
		goto cleanup;
	}

	if ((*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto cleanup;
	}

	ret = 0;

cleanup:

	evhttp_uri_free(uri);
	evhttp_clear_headers(&headers);
	free(cn);
	return (ret);
}

int
node_list_cb(const char *uid, const char *description, const char *provlink,
    const char *ipaddress, const char *status, void *arg)
{
	json_t	*array;
	json_t	*node;

	array = arg;
	node = json_object();

	json_object_set_new(node, "uid", json_string(uid));
	json_object_set_new(node, "description", json_string(description));
	json_object_set_new(node, "ipaddress", json_string(ipaddress));
	json_object_set_new(node, "provcode", json_string(provlink));
	json_object_set_new(node, "status", json_string(status));
	json_array_append_new(array, node);

	return (0);
}

int
node_list(const char *network_uid, const char *apikey, char **resp)
{
	json_t	*array;
	json_t	*jresp = NULL;
	int	 ret;

	ret = -1;

	if ((array = json_array()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto cleanup;
	}

	if (dao_node_list(network_uid, apikey, node_list_cb, array) < 0) {
		log_warnx("%s: dao_node_list", __func__);
		goto cleanup;
	}

	if ((jresp = json_object()) == NULL ||
	    (json_object_set_new(jresp, "nodes", array)) < 0 ||
	    (*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		log_warnx("%s: json_dumps", __func__);
			goto cleanup;
	}

	ret = 0;

cleanup:
	json_decref(jresp);

	return (ret);
}

int
switch_network_list_cb(void *arg, int left,
    const char *uid, const char *cert, const char *pvkey, const char *cacert)
{
	struct evbuffer		*buf = NULL;
	struct session_info	*sinfo;
	json_t			*array;
	json_t			*network;
	json_t			*resp = NULL;
	int			 ret;
	char			*resp_str = NULL;

	sinfo = arg;

	ret = -1;

	if ((network = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if ((array = json_array()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto error;
	}

	if ((resp = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(resp, "action",
	    json_string("switch-network-list")) < 0 ||
	    json_object_set_new_nocheck(network, "uid", json_string(uid)) < 0 ||
	    json_object_set_new_nocheck(network, "cert", json_string(cert)) < 0
	    || json_object_set_new_nocheck(network, "pvkey", json_string(pvkey))
	    < 0 || json_object_set_new_nocheck(network, "cacert",
	    json_string(cacert)) < 0) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if (json_array_append_new(array, network) < 0) {
		log_warnx("%s: json_array_append_new", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(resp, "networks", array) < 0) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if (left > 0) {
		if (json_object_set_new_nocheck(resp, "response",
		    json_string("more-data")) < 0) {
			log_warnx("%s: json_object_set_new_nocheck", __func__);
			goto error;
		}
	} else {
		if (json_object_set_new_nocheck(resp, "response",
		    json_string("success")) < 0) {
			log_warnx("%s: json_object_set_new_nocheck", __func__);
			goto error;
		}
	}

	if ((resp_str = json_dumps(resp, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto error;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto error;
	}

	if (evbuffer_add_reference(buf, resp_str, strlen(resp_str),
	    buf_free_cb, resp_str) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto error;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto error;
	}

	if (sinfo != NULL && sinfo->bev != NULL)
		if (bufferevent_write_buffer(sinfo->bev, buf) < 0) {
			log_warnx("%s: bufferevent_write_buffer", __func__);
			goto error;
		}

	ret = 0;

error:
	if (buf != NULL)
		evbuffer_free(buf);
	json_decref(resp);
	return (ret);
}

int
switch_network_list(struct session_info *sinfo, json_t *jmsg)
{
	struct evbuffer	*buf = NULL;
	json_t		*resp = NULL;
	char		*resp_str = NULL;

	if ((resp = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(resp, "action",
	    json_string_nocheck("switch-network-list")) < 0) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if (dao_switch_network_list(sinfo, switch_network_list_cb) < 0) {
		json_object_set_new_nocheck(resp, "response",
		    json_string_nocheck("error"));
		goto error;
	}

	json_decref(resp);
	return (0);

error:

	if ((resp_str = json_dumps(resp, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto cleanup;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto cleanup;
	}

	if (evbuffer_add_reference(buf, resp_str, strlen(resp_str),
	    buf_free_cb, resp_str) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto cleanup;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto cleanup;
	}

	if (sinfo != NULL && sinfo->bev != NULL)
		if (bufferevent_write_buffer(sinfo->bev, buf) < 0) {
			log_warnx("%s: bufferevent_write_buffer", __func__);
			goto cleanup;
		}
cleanup:
	json_decref(resp);

	return (-1);
}

int
switch_node_list_cb(void *arg, int left,
    const char *uid, const char *network_uid)
{
	struct evbuffer		*buf = NULL;
	struct session_info	*sinfo;
	json_t			*array;
	json_t			*node;
	json_t			*resp = NULL;
	int			 ret;
	char			*resp_str = NULL;

	sinfo = arg;

	ret = -1;

	if ((node = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if ((array = json_array()) == NULL) {
		log_warnx("%s: json_array", __func__);
		goto error;
	}

	if ((resp = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(resp, "action",
	    json_string("switch-node-list")) < 0 ||
	    json_object_set_new_nocheck(node, "uid", json_string(uid)) < 0 ||
	    json_object_set_new_nocheck(node, "network_uid",
	    json_string(network_uid)) < 0) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if (json_array_append_new(array, node) < 0) {
		log_warnx("%s: json_array_append_new", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(resp, "nodes", array) < 0) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if (left > 0) {
		if (json_object_set_new_nocheck(resp, "response",
		    json_string("more-data")) < 0) {
			log_warnx("%s: json_object_set_new_nocheck", __func__);
			goto error;
		}
	} else {
		if (json_object_set_new_nocheck(resp, "response",
		    json_string("success")) < 0) {
			log_warnx("%s: json_object_set_new_nocheck", __func__);
			goto error;
		}
	}

	if ((resp_str = json_dumps(resp, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto error;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto error;
	}

	if (evbuffer_add_reference(buf, resp_str, strlen(resp_str),
	    buf_free_cb, resp_str) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto error;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto error;
	}

	if (sinfo != NULL && sinfo->bev != NULL) {
		if (bufferevent_write_buffer(sinfo->bev, buf) < 0) {
			log_warnx("%s: bufferevent_write_buffer", __func__);
			goto error;
		}
	}

	ret = 0;

error:
	if (buf != NULL)
		evbuffer_free(buf);
	json_decref(resp);
	return (ret);
}

int
switch_node_list(struct session_info *sinfo, json_t *jmsg)
{
	struct evbuffer	*buf = NULL;
	json_t		*resp = NULL;
	char		*resp_str = NULL;

	if ((resp = json_object()) == NULL) {
		log_warnx("%s: json_object", __func__);
		goto error;
	}

	if (json_object_set_new_nocheck(resp, "action",
	    json_string_nocheck("switch-node-list")) < 0) {
		log_warnx("%s: json_object_set_new_nocheck", __func__);
		goto error;
	}

	if (dao_switch_node_list(sinfo, switch_node_list_cb) < 0) {
		json_object_set_new_nocheck(resp, "response",
		    json_string_nocheck("error"));
		goto error;
	}

	json_decref(resp);
	return (0);

error:

	if ((resp_str = json_dumps(resp, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto cleanup;
	}

	if ((buf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto cleanup;
	}

	if (evbuffer_add_reference(buf, resp_str, strlen(resp_str),
	    buf_free_cb, resp_str) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto cleanup;
	}

	if (evbuffer_add(buf, "\n", 1) < 0) {
		log_warnx("%s: evbuffer_add", __func__);
		goto cleanup;
	}

	if (sinfo != NULL && sinfo->bev != NULL)
		if (bufferevent_write_buffer(sinfo->bev, buf) < 0) {
			log_warnx("%s: bufferevent_write_buffer", __func__);
			goto cleanup;
		}
cleanup:
	json_decref(resp);

	return (-1);
}

int
switch_node_update_status(struct session_info *sinfo, json_t *jmsg)
{
	printf("update-node-status\n");

	char	*status;
	char	*ipsrc = NULL;
	char	*uid = NULL;
	char	*network_uid = NULL;

	json_t	*node;


	node = json_object_get(jmsg, "node");
	json_unpack(node, "{s:s}", "status", &status);
	json_unpack(node, "{s:s}", "ipsrc", &ipsrc);
	json_unpack(node, "{s:s}", "uid", &uid);
	json_unpack(node, "{s:s}", "networkuid", &network_uid);

	dao_update_node_status(network_uid, uid, status, ipsrc);

	return (0);
}

