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

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <jansson.h>

#include <logger.h>
#include "context.h"
#include "control.h"
#include "session.h"

int pipefd[2];

static struct event_base		*base;
static struct bufferevent		*bufev_sock = NULL;
static struct bufferevent		*bufev_pipe = NULL;
static struct switch_cfg		*cfg = NULL;
static passport_t			*passport = NULL;

#define MAX_SESSION 4096
static struct session *session_tracking_table[MAX_SESSION];
static uint32_t tracking_id = 0;

static int del_node(json_t *);
static int del_network(json_t *);
static int provisioning(json_t *);
static int listall_node(json_t *);
static int listall_network(json_t *);
static void sighandler(evutil_socket_t, short, void *);
static int dispatch_op(json_t *);
static void on_read_cb(struct bufferevent *, void *);
static void on_event_cb(struct bufferevent *, short, void *);
static DH *get_dh_1024();
static SSL_CTX *evssl_init();

int
del_node(json_t *jmsg)
{
	char		*netid;
	char		*uuid;
	json_t		*node;
	struct session	*session;
	context_t	*context;

	if ((node = json_object_get(jmsg, "node")) == NULL) {
		jlog(L_ERROR, "json_object_get failed");
		return -1;
	}

	if (json_unpack(node, "{s:s}", "uuid", &uuid) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if (json_unpack(node, "{s:s}", "netid", &netid) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if ((context = context_lookup(atoi(netid))) == NULL) {
		jlog(L_ERROR, "context_lookup failed");
		return -1;
	}

	/* remove the node from the access table */
	ctable_erase(context->atable, uuid);

	/* if the node is connected, mark it to be purged */
	if ((session = ctable_find(context->ctable, uuid)) == NULL) {
		session->state = SESSION_STATE_PURGE;
	}

	return 0;
}

int
del_network(json_t *jmsg)
{
	char		*netid;
	json_t		*network;
	context_t	*context;
	struct session	*session_list;

	if ((network = json_object_get(jmsg, "network")) == NULL) {
		jlog(L_ERROR, "json_object_get failed");
		return -1;
	}

	if (json_unpack(network, "{s:s}", "netid", &netid) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if ((context = context_disable(atoi(netid))) == NULL) {
		jlog(L_ERROR, "context_disable failed");
		return -1;
	}

	session_list = context->session_list;
	while (session_list != NULL) {
		session_list->state = SESSION_STATE_PURGE;
		session_list->context = NULL;
		session_list = session_list->next;
	}

	context_free(context);

	return 0;
}

int
provisioning(json_t *jmsg)
{
	char		*cert;
	char		*ipaddr;
	char		*pkey;
	char		*response;
	char		*tcert;
	char		*tid;
	json_t		*node;
	struct session	*session;

	if (json_unpack(jmsg, "{s:s}", "response", &response) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if (strcmp(response, "success") != 0) {
		jlog(L_ERROR, "provisioning != success");
		return -1;
	}

	if (json_unpack(jmsg, "{s:s}", "tid", &tid) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if ((node = json_object_get(jmsg, "node")) == NULL) {
		jlog(L_ERROR, "json_object_get failed");
		return -1;
	}

	if (json_unpack(node, "{s:s}", "cert", &cert) == -1 ||
	    json_unpack(node, "{s:s}", "pkey", &pkey) == -1 ||
	    json_unpack(node, "{s:s}", "tcert", &tcert) == -1 ||
	    json_unpack(node, "{s:s}", "ipaddr", &ipaddr) == -1) {
		jlog(L_ERROR, "NULL parameter");
		return -1;
	}

	DNDSMessage_t *new_msg;
	DNDSMessage_new(&new_msg);
	DNDSMessage_set_channel(new_msg, 0);
	DNDSMessage_set_pdu(new_msg, pdu_PR_dnm);

	DNMessage_set_operation(new_msg, dnop_PR_provResponse);

	ProvResponse_set_certificate(new_msg, cert, strlen(cert));
	ProvResponse_set_certificateKey(new_msg, (uint8_t*)pkey, strlen(pkey));
	ProvResponse_set_trustedCert(new_msg, (uint8_t*)tcert, strlen(tcert));
	ProvResponse_set_ipAddress(new_msg, ipaddr);

	session = session_tracking_table[atoi(tid) % MAX_SESSION];
	session_tracking_table[atoi(tid) % MAX_SESSION] = NULL;
	if (session)
		net_send_msg(session->netc, new_msg);
	DNDSMessage_del(new_msg);

	/* XXX
	 * If the provisioning is not a success,
	 * we must disconnect the client.
	 */

	return 0;
}

int
listall_node(json_t *jmsg)
{
	char		*uuid;
	char		*netid;
	char		*response;
	size_t		 array_size;
	size_t		 i;
	json_t		*js_nodes;
	json_t		*node;
	context_t	*context;

	if ((js_nodes = json_object_get(jmsg, "nodes")) == NULL) {
		jlog(L_ERROR, "json_object_get failed");
		return -1;
	}

	if ((array_size = json_array_size(js_nodes)) == 0) {
		jlog(L_ERROR, "json_array_size failed");
		return -1;
	}

	for (i = 0; i < array_size; i++) {

		if ((node = json_array_get(js_nodes, i)) == NULL) {
			jlog(L_ERROR, "json_array_get failed");
			return -1;
		}

		if (json_unpack(node, "{s:s}", "uuid", &uuid) == -1 ||
		    json_unpack(node, "{s:s}", "netid", &netid) == -1) {
			jlog(L_ERROR, "NULL parameter");
			return -1;
		}

		if ((context = context_lookup(atoi(netid))) != NULL) {
			ctable_insert(context->atable, uuid, context->access_session);
		}
	}

	if ((json_unpack(jmsg, "{s:s}", "response", &response)) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if (strcmp(response, "success") == 0) {
		return 0;
	}

	return 1;
}

int
listall_network(json_t *jmsg)
{
	char	*uuid;
	char	*subnet;
	char	*netmask;
	char	*cert;
	char	*pkey;
	char	*tcert;
	char	*response;
	size_t	 i;
	size_t	 array_size;
	json_t	*js_networks;
	json_t	*elm;

	if ((js_networks = json_object_get(jmsg, "networks")) == NULL) {
		jlog(L_ERROR, "json_object_get failed");
		return -1;
	}

	if ((array_size = json_array_size(js_networks)) == 0) {
		jlog(L_ERROR, "json_array_size failed");
		return -1;
	}

	for (i = 0; i < array_size; i++) {

		if ((elm = json_array_get(js_networks, i)) == NULL) {
			jlog(L_ERROR, "json_array_get failed");
			return -1;
		}

		if (json_unpack(elm, "{s:s}", "uuid", &uuid) == -1 ||
		    json_unpack(elm, "{s:s}", "network", &subnet) == -1 ||
		    json_unpack(elm, "{s:s}", "netmask", &netmask) == -1 ||
		    json_unpack(elm, "{s:s}", "cert", &cert) == -1 ||
		    json_unpack(elm, "{s:s}", "pkey", &pkey) == -1 ||
		    json_unpack(elm, "{s:s}", "tcert", &tcert) == -1) {
			jlog(L_ERROR, "NULL parameter");
			return -1;
		}
		context_create(uuid, subnet, netmask, cert, pkey, tcert);
	}

	if ((json_unpack(jmsg, "{s:s}", "response", &response)) == -1) {
		jlog(L_ERROR, "json_unpack failed");
		return -1;
	}

	if (strcmp(response, "success") == 0) {
		return 0;
	}

	return 1;
}

int
query_provisioning(struct session *session, char *provcode)
{
	jlog(L_DEBUG, "query provisioning");

	char	*query_str = NULL;
	char	 tid[10];
	json_t	*node = NULL;
	json_t	*query = NULL;

	sprintf(tid, "%d", tracking_id);
	session_tracking_table[tracking_id % MAX_SESSION] = session;

	if ((query = json_object()) == NULL) {
		jlog(L_ERROR, "json_object failed");
		goto out;
	}

	if (json_object_set_new(query, "tid", json_string(tid)) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if (json_object_set_new(query, "action", json_string("provisioning")) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((node = json_object()) == NULL) {
		jlog(L_ERROR, "json_object failed");
		goto out;
	}

	if (json_object_set_new(query, "node", node) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if (json_object_set_new(node, "provcode", json_string(provcode)) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		jlog(L_ERROR, "json_dumps failed");
		goto out;
	}

	write(pipefd[1], query_str, strlen(query_str));

	json_decref(query);
	free(query_str);
	return 0;

out:
	json_decref(query);
	free(query_str);
	return -1;
}

int
query_list_node()
{
	jlog(L_DEBUG, "query list node");

	char	*query_str = NULL;
	json_t	*query = NULL;

	if ((query = json_object()) == NULL) {
		jlog(L_ERROR, "json_object failed");
		goto out;
	}

	if (json_object_set_new(query, "tid", json_string("tid")) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if (json_object_set_new(query, "action", json_string("listall-node")) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		jlog(L_ERROR, "json_dumps failed");
		goto out;
	}

	if (bufferevent_write(bufev_sock, query_str, strlen(query_str)) == -1) {
		jlog(L_ERROR, "bufferevent_write failed");
		goto out;
	}

	if (bufferevent_write(bufev_sock, "\n", strlen("\n")) == -1) {
		jlog(L_ERROR, "bufferevent_write failed");
		goto out;
	}

	json_decref(query);
	free(query_str);
	return 0;

out:
	json_decref(query);
	free(query_str);
	return -1;
}

int
update_node_status(char *status, char *local_ipaddr, char *cert_name)
{
	jlog(L_DEBUG, "update node status");

	char	*query_str = NULL;
	json_t	*query = NULL;
	json_t	*node = NULL;

	if ((query = json_object()) == NULL) {
		jlog(L_ERROR, "json_object failed");
		goto out;
	}

	if ((json_object_set_new(query, "action", json_string("update-node-status"))) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((node = json_object()) == NULL) {
		jlog(L_ERROR, "json_object failed");
		goto out;
	}

	if ((json_object_set_new(query, "node", node)) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((json_object_set_new(node, "status", json_string(status))) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((json_object_set_new(node, "local-ipaddr", json_string(local_ipaddr))) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((json_object_set_new(node, "cert-name", json_string(cert_name))) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		jlog(L_ERROR, "json_dumps failed");
		goto out;
	}

	write(pipefd[1], query_str, strlen(query_str));

	json_decref(query);
	free(query_str);
	return 0;

out:
	json_decref(query);
	free(query_str);
	return -1;
}

int
query_list_network()
{
	jlog(L_DEBUG, "list network");

	char	*query_str = NULL;
	json_t	*query = NULL;

	if ((query = json_object()) == NULL) {
		jlog(L_ERROR, "json_object failed");
		goto out;
	}

	if (json_object_set_new(query, "action", json_string("listall-network")) == -1) {
		jlog(L_ERROR, "json_object_set_new failed");
		goto out;
	}

	if ((query_str = json_dumps(query, 0)) == NULL) {
		jlog(L_ERROR, "json_dumps failed");
		goto out;
	}

	if (bufferevent_write(bufev_sock, query_str, strlen(query_str)) == -1) {
		jlog(L_ERROR, "bufferevent_write failed");
		goto out;
	}

	if (bufferevent_write(bufev_sock, "\n", strlen("\n")) == -1) {
		jlog(L_ERROR, "bufferevent_write failed");
		goto out;
	}

	json_decref(query);
	free(query_str);
	return 0;

out:
	json_decref(query);
	free(query_str);
	return -1;
}

void
sighandler(evutil_socket_t sk, short t, void *ptr)
{
	struct event_base	*ev_base;
	jlog(L_DEBUG, "sighandler!");

	ev_base = (struct event_base *)ptr;
	event_base_loopbreak(ev_base);
}

int
dispatch_op(json_t *jmsg)
{
	char	*action;
	int	 ret = 0;

	if (json_unpack(jmsg, "{s:s}", "action", &action) == -1)
		return -1;

	if (strcmp(action, "listall-network") == 0) {
		if ((ret = listall_network(jmsg)) == 0) {
			/* all network are now fetched */
			if (cfg->ctrl_initialized == 0) {
				/* if not yet initialized... */
				cfg->ctrl_initialized = 1;
				ret = query_list_node(jmsg);
			}
		}
	} else if (strcmp(action, "listall-node") == 0) {
		ret = listall_node(jmsg);
	} else if (strcmp(action, "provisioning") == 0) {
		ret = provisioning(jmsg);
	} else if (strcmp(action, "del-network") == 0) {
		ret = del_network(jmsg);
	} else if (strcmp(action, "del-node") == 0) {
		ret = del_node(jmsg);
	}

	return ret;
}

void
pipe_read_cb(struct bufferevent *bev, void *arg)
{
	char query_str[1024] = {0};

	bufferevent_read(bev, query_str, sizeof(query_str));
	printf("tmp: %s\n", query_str);

	if (bufferevent_write(bufev_sock, query_str, strlen(query_str)) == -1) {
		jlog(L_ERROR, "bufferevent_write failed");
		return;
	}

	if (bufferevent_write(bufev_sock, "\n", strlen("\n")) == -1) {
		jlog(L_ERROR, "bufferevent_write failed");
		return;
	}
}


void
on_read_cb(struct bufferevent *bev, void *arg)
{
	jlog(L_DEBUG, "on_read_cb");

	char			*str = NULL;
	size_t			n_read_out;
	json_error_t		error;
	json_t			*jmsg = NULL;

	if ((str = evbuffer_readln(bufferevent_get_input(bev),
	    &n_read_out, EVBUFFER_EOL_LF)) == NULL) {
		return;
	}

	printf("str: %d <> %s\n\n\n", strlen(str), str);
	if ((jmsg = json_loadb(str, n_read_out, 0, &error)) == NULL) {
		jlog(L_ERROR, "json_loadb: %s", error.text);
		bufferevent_free(bufev_sock);
		return;
	}

	dispatch_op(jmsg);
	json_decref(jmsg);
}

void
pipe_event_cb(struct bufferevent *bufev_sock, short events, void *arg)
{
	printf("on_event_cb\n");
}

void
on_event_cb(struct bufferevent *bufev_sock, short events, void *arg)
{
	unsigned long e = 0;

	if (events & BEV_EVENT_CONNECTED) {
		jlog(L_DEBUG, "connected");
		query_list_network();
	} else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		jlog(L_DEBUG, "disconnected");
		while ((e = bufferevent_get_openssl_error(bufev_sock)) > 0) {
			jlog(L_ERROR, "%s", ERR_error_string(e, NULL));
		}
	}
}

DH *
get_dh_1024() {

	DH *dh = NULL;
	static unsigned char dh1024_p[]={
		0xDE,0xD3,0x80,0xD7,0xE1,0x8E,0x1B,0x5D,0x5C,0x76,0x61,0x79,
		0xCA,0x8E,0xCD,0xAD,0x83,0x49,0x9E,0x0B,0xC0,0x2E,0x67,0x33,
		0x5F,0x58,0x30,0x9C,0x13,0xE2,0x56,0x54,0x1F,0x65,0x16,0x27,
		0xD6,0xF0,0xFD,0x0C,0x62,0xC4,0x4F,0x5E,0xF8,0x76,0x93,0x02,
		0xA3,0x4F,0xDC,0x2F,0x90,0x5D,0x77,0x7E,0xC6,0x22,0xD5,0x60,
		0x48,0xF5,0xFB,0x5D,0x46,0x5D,0xF5,0x97,0x20,0x35,0xA6,0xEE,
		0xC0,0xA0,0x89,0xEE,0xAB,0x22,0x68,0x96,0x8B,0x64,0x69,0xC7,
		0xEB,0x41,0xDF,0x74,0xDF,0x80,0x76,0xCF,0x9B,0x50,0x2F,0x08,
		0x13,0x16,0x0D,0x2E,0x94,0x0F,0xEE,0x29,0xAC,0x92,0x7F,0xA6,
		0x62,0x49,0x41,0x0F,0x54,0x39,0xAD,0x91,0x9A,0x23,0x31,0x7B,
		0xB3,0xC9,0x34,0x13,0xF8,0x36,0x77,0xF3,
	};

	static unsigned char dh1024_g[]={
		0x02,
	};

	if ((dh = DH_new()) == NULL) {
		return NULL;
	}

	dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
	dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

	if (dh->p == NULL || dh->g == NULL) {
		DH_free(dh);
		return NULL;
	}

	return dh;
}

SSL_CTX *
evssl_init()
{
	DH		*dh;
	SSL_CTX		*ctx;

	SSL_load_error_strings();
	SSL_library_init();
	RAND_poll();

	if ((passport = pki_passport_load_from_file(cfg->cert,
	    cfg->pkey, cfg->tcert)) == NULL) {
		return NULL;
	}

	if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
		jlog(L_ERROR, "SSL_CTX_new failed");
		return NULL;
	}

	if ((dh = get_dh_1024()) == NULL) {
		jlog(L_ERROR, "get_dh_1024 failed");
		goto out;
	}

	if ((SSL_CTX_set_tmp_dh(ctx, dh)) == 0) {
		jlog(L_ERROR, "SSL_CTX_set_tmp_dh failed");
		goto out;
	}

	//SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
	if ((SSL_CTX_set_cipher_list(ctx, "AES256-GCM-SHA384")) == 0) {
		jlog(L_ERROR, "SSL_CTX_set_cipher failed");
		goto out;
	}

	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	if ((SSL_CTX_use_certificate(ctx, passport->certificate)) == 0) {
		jlog(L_ERROR, "SSL_CTX_use_certificate failed");
		goto out;
	}

	if ((SSL_CTX_use_PrivateKey(ctx, passport->keyring)) == 0) {
		jlog(L_ERROR, "SSL_CTX_use_PrivateKey failed");
		goto out;
	}

	DH_free(dh);
	return ctx;

out:
	DH_free(dh);
	SSL_CTX_free(ctx);
	return NULL;
}

int
ctrl_init(struct switch_cfg *_cfg)
{
	int			 fd = -1;
	int			 flag = 1;
	struct sockaddr_in	 sin;
	static struct event	*ev_int;
	SSL_CTX			*ctx;
	SSL			*ssl;

	cfg = _cfg;
	cfg->ctrl_running = 1;

	jlog(L_NOTICE, "Control initializing...");

	if ((base = event_base_new()) == NULL) {
		jlog(L_ERROR, "event_base_new failed");
		goto out;
	}

	if ((ev_int = evsignal_new(base, SIGHUP, sighandler, NULL)) == NULL) {
		jlog(L_ERROR, "evsignal_new failed");
		goto out;
	}

	if (event_add(ev_int, NULL) < 0) {
		jlog(L_ERROR, "event_add failed");
		goto out;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(9093);

	if ((fd = socket(sin.sin_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		jlog(L_ERROR, "socket failed");
		goto out;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		jlog(L_ERROR, "setsockopt failed");
		goto out;
	}

	if (evutil_make_socket_nonblocking(fd) < 0) {
		jlog(L_ERROR, "evutil_make_socket_nonblocking failed");
		goto out;
	}	

	if ((ctx = evssl_init()) == NULL) {
		jlog(L_ERROR, "evssl_init failed");
		goto out;
	}

	if ((ssl = SSL_new(ctx)) == NULL) {
		jlog(L_ERROR, "SSL_new failed");
		goto out;
	}

	if ((bufev_sock = bufferevent_openssl_socket_new(base, fd, ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		jlog(L_ERROR, "bufferevent_socket_new failed");
		goto out;
	}

	bufferevent_enable(bufev_sock, EV_READ|EV_WRITE);
	bufferevent_setcb(bufev_sock, on_read_cb, NULL, on_event_cb, NULL);

	if (bufferevent_socket_connect(bufev_sock,
	    (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		jlog(L_ERROR, "bufferevent_socket_connected failed");
		goto out;
	}

	bufev_pipe = bufferevent_socket_new(base, pipefd[0], BEV_OPT_CLOSE_ON_FREE);
	bufferevent_enable(bufev_pipe, EV_READ|EV_WRITE);
	bufferevent_setcb(bufev_pipe, pipe_read_cb, NULL, pipe_event_cb, NULL);

	event_base_dispatch(base);

	if (bufev_sock != NULL) {
		bufferevent_free(bufev_sock);
	}

	event_base_free(base);
	return 0;

out:
	if (bufev_sock != NULL)
		bufferevent_free(bufev_sock);
	event_base_free(base);
	return -1;
}

void
ctrl_fini()
{
	pki_passport_destroy(passport);
	contexts_free();
}
