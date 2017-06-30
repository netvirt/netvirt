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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <jansson.h>

#include <log.h>
#include <pki.h>

#include "dao.h"
#include "ippool.h"
#include "request.h"

extern struct session_info *switch_sinfo;

int
client_create(char *msg)
{
	json_t		*jmsg = NULL;
	json_error_t	 error;
	int		 ret;
	char		*email;
	char		*password;
	char		*apikey = NULL;

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

	// XXX send email !
	FILE	*tmp;
	tmp = fopen("/tmp/apikey", "w");
	fprintf(tmp, "%s", apikey);
	fclose(tmp);

	ret = 0;

cleanup:
	json_decref(jmsg);
	free(apikey);
	return (ret);
}

int
client_activate(char *msg)
{
	json_t		*jmsg;
	json_error_t	 error;
	int		 ret = 0;
	char		*apikey = NULL;
	char		*new_apikey = NULL;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}

	json_unpack(jmsg, "{s:s}", "apikey", &apikey);
	if (apikey == NULL) {
		ret = -1;
		goto cleanup;
	}

	if ((new_apikey = pki_gen_key()) == NULL) {
		ret = -1;
		goto cleanup;
	}

	if (dao_client_activate(apikey) == -1) {
		ret = -1;
		goto cleanup;
	}

	if (dao_client_update_apikey(apikey, new_apikey) < 0) {
		ret = -1;
		goto cleanup;
	}

cleanup:
	json_decref(jmsg);
	free(new_apikey);
	return (ret);
	
}

int
client_get_newapikey(char *msg, char **resp)
{
	json_t		*jmsg;
	json_t		*jclient = NULL;
	json_t		*jresp = NULL;
	json_error_t	 error;
	int		 ret = 0;
	char		*email = NULL;
	char		*password = NULL;
	char		*new_apikey = NULL;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}
	printf("%d\n", __LINE__);
 
	json_unpack(jmsg, "{s:s}", "email", &email);
	if (email == NULL) {
		ret = -1;
		goto cleanup;
	}

	printf("%d\n", __LINE__);
	json_unpack(jmsg, "{s:s}", "password", &password);
	if (password == NULL) {
		ret = -1;
		goto cleanup;
	}

	printf("%d\n", __LINE__);
	if ((new_apikey = pki_gen_key()) == NULL) {
		ret = -1;
		goto cleanup;
	}

	printf("%d\n", __LINE__);
	if (dao_client_update_apikey2(email, password, new_apikey) < 0) {
		ret = -1;
		goto cleanup;
	}

	printf("%d\n", __LINE__);
	jresp = json_object();
	jclient = json_object();
	json_object_set_new(jresp, "client", jclient);
	json_object_set_new(jclient, "apikey", json_string(new_apikey));
	*resp = json_dumps(jresp, JSON_INDENT(1));

	printf("%d\n", __LINE__);
cleanup:
	json_decref(jmsg);
	json_decref(jresp);
	free(new_apikey);

	return (ret);
}

int
client_get_newresetkey(char *msg, char **resp)
{
	json_t		*jmsg;
	json_t		*jclient = NULL;
	json_t		*jresp = NULL;
	json_error_t	 error;
	int		 ret = 0;
	char		*email = NULL;
	char		*resetkey = NULL;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}

	json_unpack(jmsg, "{s:s}", "email", &email);
	if (email == NULL) {
		ret = -1;
		goto cleanup;
	}

	if ((resetkey = pki_gen_key()) == NULL) {
		ret = -1;
		goto cleanup;
	}

	if (dao_client_update_resetkey(email, resetkey) < 0) {
		ret = -1;
		goto cleanup;
	}

	jresp = json_object();
	jclient = json_object();
	json_object_set_new(jresp, "client", jclient);
	json_object_set_new(jclient, "resetkey", json_string(resetkey));
	*resp = json_dumps(jresp, JSON_INDENT(1));

cleanup:
	json_decref(jmsg);
	json_decref(jresp);
	free(resetkey);

	return (ret);
}

int
client_reset_password(char *msg)
{
	json_t		*jmsg;
	json_error_t	 error;
	char		*email = NULL;
	char		*resetkey = NULL;
	char		*newpassword = NULL;
	int		 ret = 0;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}

	json_unpack(jmsg, "{s:s}", "email", &email);
	if (email == NULL) {
		ret = -1;
		goto cleanup;
	}

	json_unpack(jmsg, "{s:s}", "resetkey", &resetkey);
	if (resetkey == NULL) {
		ret = -1;
		goto cleanup;
	}

	json_unpack(jmsg, "{s:s}", "newpassword", &newpassword);
	if (newpassword == NULL) {
		ret = -1;
		goto cleanup;
	}

	if (dao_client_update_password(email, resetkey, newpassword) < 0) {
		ret = -1;
		goto cleanup;
	}

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
	char		*cidr = NULL;
	char		*emb_cert_ptr = NULL;
	char		*emb_pvkey_ptr = NULL;
	char		*serv_cert_ptr = NULL;
	char		*serv_pvkey_ptr = NULL;
	char		 emb_serial[10];

	if (msg == NULL || apikey == NULL)
		return (-1);
	
	if (dao_client_get_id(&client_id, apikey) < 0)
		return (-1);

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}

	json_unpack(jmsg, "{s:s}", "description", &description);
	if (description == NULL) {
		ret = -1;
		goto cleanup;
	}

	json_unpack(jmsg, "{s:s}", "cidr", &cidr);
	if (description == NULL) {
		ret = -1;
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
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);

	network_uid = pki_gen_uid();
	ret = dao_network_create(client_id,
				network_uid,
				description,
				"44.128.0.0/16",
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

		json_object_set_new(fwd_resp, "action", json_string("listall-network"));
		json_object_set_new(fwd_resp, "response", json_string("more-data"));

		json_object_set_new(network, "uid", json_string(network_uid));
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

cleanup:

	json_decref(jmsg);
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
	int	 ret = 0;

	array = json_array();
	if (dao_network_list(apikey, network_list_cb, array) < 0) {
		ret = -1;
		goto cleanup;
	}

	jresp = json_object();
	json_object_set_new(jresp, "networks", array);
	*resp = json_dumps(jresp, JSON_INDENT(1));

cleanup:
	json_decref(jresp);

	return (ret);
}

int
network_delete(const char *uid, const char *apikey)
{
	int		 ret = 0;

	if (uid == NULL || apikey == NULL)
		return (-1);

/*	FIXME
	dao_node_delete_all(network_uid);
*/

	if (dao_network_delete(uid, apikey) < 0) {
		ret = -1;
		goto cleanup;
	}

	/* Forward del-network to the switch */
#if 0
	char *fwd_str = NULL;
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
#endif
cleanup:
	return (ret);
}

int
node_create(const char *msg, const char *apikey)
{
	json_t		*jmsg;
	json_error_t	 error;
	struct ippool	*ippool = NULL;
	long		 size;
	int		 ret = 0;
	int		 pool_size;
	char		*client_id = NULL;
	char		*uid;
	char		*key = NULL;
	char		*network_uid = NULL;
	char		*description = NULL;
	char		*ip = NULL;
	unsigned char	*ippool_bin = NULL;
	char		 provkey[256];

	if (msg == NULL || apikey == NULL)
		return (-1);

	if (dao_client_get_id(&client_id, apikey) < 0)
		return (-1);

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}

	json_unpack(jmsg, "{s:s}", "network_uid", &network_uid);
	if (network_uid == NULL) {
		ret = -1;
		goto cleanup;
	}

	json_unpack(jmsg, "{s:s}", "description", &description);
	if (description == NULL) {
		ret = -1;
		goto cleanup;
	}

	/* handle ip pool 
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ip = ippool_get_ip(ippool);

	ret = dao_network_update_ippool(network_uid, ippool->pool, pool_size);
	if (ret == -1) {
	}

	*/

	if ((uid = pki_gen_uid()) == NULL) {
		ret = -1;
		goto cleanup;
	}

	if ((key = pki_gen_key()) == NULL) {
		ret = -1;
		goto cleanup;
	}

	snprintf(provkey, sizeof(provkey), "%s:%s:%s", network_uid, uid, provkey);
	if (dao_node_create(network_uid, uid, provkey, description, "192.168.1.1") < 0) {
		ret = -1;
		goto cleanup;
	}
#if 0
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
#endif

cleanup:
	ippool_free(ippool);
	free(key);
	json_decref(jmsg);
	free(client_id);

	return (ret);
}

int
node_delete(const char *uid, const char *apikey)
{
	int		ret = 0;
	char		*ipaddr = NULL;
	struct ippool	*ippool = NULL;
	int		 pool_size;


	if (uid == NULL || apikey == NULL)
		return (-1);

#if 0
	ret = dao_fetch_node_ip(network_uuid, node_uuid, &ipaddr);

	unsigned char *ippool_bin = NULL;
	ret = dao_fetch_context_ippool(network_uuid, &ippool_bin);

	/* update ip pool */
	ippool = ippool_new("44.128.0.0", "255.255.0.0");
	free(ippool->pool);
	ippool->pool = (uint8_t*)ippool_bin;
	pool_size = (ippool->hosts+7)/8 * sizeof(uint8_t);
	ippool_release_ip(ippool, ipaddr);

	ret = dao_update_context_ippool(network_uuid, ippool->pool, pool_size);
#endif

	if (dao_node_delete(uid, apikey) < 0) {
		ret = -1;
		goto cleanup;
	}

#if 0
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
#endif
cleanup:
	return (ret);
}

int
node_provisioning(const char *msg, char **resp)
{
	json_t		*jmsg;
	json_t		*jresp;
	json_error_t	 error;
	int		 ret = 0;
	uint8_t		 i;
	char		*cn = NULL;
	char		*csr;
	char		*provkey;
	char		*str;
	char		*network_uid;
	char		*node_uid;
	char		*key;
	char		*tokens[3];
	char		*p;
	char		*last;
	char		*cacert;
	char		*pvkey;
	char		*serial;
	char		*node_cert;

	if ((jmsg = json_loadb(msg, strlen(msg), 0, &error)) == NULL) {
		warnx("json_loadb: %s", error.text);
		return (-1);
	}

	if (json_unpack(jmsg, "{s:s,s:s}", "csr", &csr, "provkey", &provkey)
	    < 0)
		return (-1);

	printf("prov key : %s\n", provkey);

	if ((str = strdup(provkey)) == NULL)
		return (-1);
        for ((i = 0, p = strtok_r(str, ":", &last)); p;
            (p = strtok_r(NULL, ":", &last))) {
                if (i < sizeof(tokens)) {
			printf("%s\n", p);
                        tokens[i++] = p;
		}
        }
        tokens[i] = NULL;

        if ((network_uid = tokens[0]) == NULL ||
	    (node_uid = tokens[1]) == NULL ||
	    (key = tokens[2]) == NULL) {
		log_warnx("%s: Invalid provkey tokens", __func__);
		return (-1);
	}

	if (dao_node_delete_provkey(network_uid, node_uid, provkey) < 0)
		return (-1);

	if (dao_network_get_embassy(network_uid, &cacert, &pvkey, &serial) < 0)
		return (-1);

	if (asprintf(&cn, "1:nva:%s:%s", network_uid, node_uid) < 0) {
		ret = -1;
		goto cleanup;
	}

	if ((node_cert = pki_deliver_cert_from_certreq(csr, cacert, pvkey,
	    atoi(serial), cn)) == NULL) { // XXX remove atoi()
		ret = -1;
		goto cleanup;
	}

	if ((jresp = json_object()) == NULL) {
		ret = -1;
		goto cleanup;
	}

	if (json_object_set_new_nocheck(jresp, "cert", json_string(node_cert)) < 0) {
		ret = -1;
		goto cleanup;
	}

	if (json_object_set_new_nocheck(jresp, "cacert", json_string(cacert)) < 0) {
		ret = -1;
		goto cleanup;
	}

	if ((*resp = json_dumps(jresp, JSON_INDENT(1))) == NULL) {
		ret = -1;
		goto cleanup;
	}

cleanup:
	free(cn);
	return (ret);
}

int
node_list_cb(const char *uid, const char *description, const char *provkey,
    const char *ipaddress, const char *status, void *arg)
{
	json_t	*array;
	json_t	*node;

	array = arg;
	node = json_object();

	json_object_set_new(node, "uid", json_string(uid));
	json_object_set_new(node, "description", json_string(description));
	json_object_set_new(node, "ipaddress", json_string(ipaddress));
	json_object_set_new(node, "provcode", json_string(provkey));
	json_object_set_new(node, "status", json_string(status));
	json_array_append_new(array, node);

	return (0);
}

int
node_list(const char *network_uid, const char *apikey, char **resp)
{
	json_t	*array;
	json_t	*jresp = NULL;
	int	 ret = 0;

	array = json_array();

	if (dao_node_list(network_uid, apikey, node_list_cb, array) < 0) {
		ret = -1;
		goto cleanup;
	}

	jresp = json_object();
	json_object_set_new(jresp, "nodes", array);
	*resp = json_dumps(jresp, JSON_INDENT(1));

cleanup:
	json_decref(jresp);

	return (ret);
}

int
switch_network_list_cb(void *arg, int left,
    char *uid, char *cert, char *pvkey, char *cacert)
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

	if (evbuffer_add_reference(buf, resp_str, strlen(resp_str), NULL, NULL)
	    < 0) {
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
	free(resp_str);
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

	if (evbuffer_add_reference(buf, resp_str, strlen(resp_str), NULL, NULL)
	    < 0) {
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
	if (buf != NULL)
		evbuffer_free(buf);
	json_decref(resp);
	free(resp_str);

	return (-1);
}

int
switch_node_update_status(struct session_info *sinfo, json_t *jmsg)
{
#if 0
	//jlog(L_DEBUG, "update-node-status");

	char	*status;
	char	*local_ipaddr = NULL;
	char	*uuid = NULL;
	char	*network_uuid = NULL;

	json_t	*node;


	node = json_object_get(jmsg, "node");
	json_unpack(node, "{s:s}", "status", &status);
	json_unpack(node, "{s:s}", "local-ipaddr", &local_ipaddr);
	json_unpack(node, "{s:s}", "uuid", &uuid);
	json_unpack(node, "{s:s}", "networkuuid", &network_uuid);

	dao_update_node_status(network_uuid, uuid, status, local_ipaddr);

	json_decref(node);
#endif

	return;
}

int
switch_node_list_cb(void *arg, int remaining, char *network_uuid, char *uuid)
{
#if 0
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
#endif
	return -1;
}

int
switch_node_list(struct session_info *sinfo, json_t *jmsg)
{
#if 0
	//jlog(L_DEBUG, "listallNode");

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
#endif
	return;

}



