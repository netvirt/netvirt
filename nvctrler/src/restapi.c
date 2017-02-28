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

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>

#include <jansson.h>

#include <string.h>
#include <err.h>

#include "request.h"

void
v1_client_create_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	int			 code = HTTP_BADREQUEST;
	const char		*type;
	const char		*phrase = "Bad Request";
	void			*p;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST)
		goto cleanup;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if (client_create(p) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	code = 201;
	phrase = "Created";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_client_activate_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	int			 code = HTTP_BADREQUEST;
	const char		*type;
	const char		*phrase = "Bad Request";
	void			*p;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST)
		goto cleanup;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if (client_activate(p) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	code = HTTP_OK; 
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_client_get_newapikey_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	struct evbuffer		*respbuf = NULL;
	int			 code = HTTP_BADREQUEST;
	const char		*type;
	const char		*phrase = "Bad Request";
	char			*msg;
	void			*p;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
		goto cleanup;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if (client_get_newapikey(p, &msg) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0)
		goto cleanup;

	if ((respbuf = evbuffer_new()) == NULL)
		goto cleanup;

	if (evbuffer_add_reference(respbuf, msg, strlen(msg), NULL, NULL) < 0)
		goto cleanup;

	code = HTTP_OK;
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
}

void
v1_client_get_newresetkey_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	struct evbuffer		*respbuf = NULL;
	int			 code = HTTP_BADREQUEST;
	const char		*type;
	const char		*phrase = "Bad Request";
	char			*msg;
	void			*p;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET)
		goto cleanup;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if (client_get_newresetkey(p, &msg) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0)
		goto cleanup;

	if ((respbuf = evbuffer_new()) == NULL)
		goto cleanup;

	if (evbuffer_add_reference(respbuf, msg, strlen(msg), NULL, NULL) < 0)
		goto cleanup;

	code = HTTP_OK; 
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
}

void
v1_client_update_password_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	int			 code = HTTP_BADREQUEST;
	const char		*type;
	const char		*phrase = "Bad Request";
	void			*p;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST)
		goto cleanup;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if (client_reset_password(p) == -1) {
		code = 403;
		phrase = "Forbidden"; 
		goto cleanup;
	}

	code = HTTP_OK;
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_network_create(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	int			 code = HTTP_BADREQUEST;
	const char		*apikey;
	const char		*type;
	const char		*phrase = "Bad Request";
	void			*p;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if ((apikey = evhttp_find_header(headers, "X-netvirt-apikey")) == NULL)
		goto cleanup;

	if (network_create(p, apikey) == -1) {
		code = 403;
		phrase = "Forbidden"; 
		goto cleanup;
	}

	code = 201;
	phrase = "Created";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_network_delete(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	 qheaders = TAILQ_HEAD_INITIALIZER(qheaders);
	struct evkeyvalq	*headers;
	const struct evhttp_uri	*uri;
	int			 code = HTTP_BADREQUEST;
	const char		*apikey;
	const char		*phrase = "Bad Request";
	const char		*uid;
	const char		*query;

	if ((headers = evhttp_request_get_input_headers(req)) == NULL)
		goto cleanup;

	if ((apikey = evhttp_find_header(headers, "X-netvirt-apikey")) == NULL)
		goto cleanup;

	if ((uri = evhttp_request_get_evhttp_uri(req)) == NULL)
		goto cleanup;

	if ((query = evhttp_uri_get_query(uri)) == NULL)
		goto cleanup;

	if (evhttp_parse_query_str(query, &qheaders) < 0)
		goto cleanup;

	if ((uid = evhttp_find_header(&qheaders, "uid")) == NULL)
		goto cleanup;

	if (network_delete(uid, apikey) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	code = 204;
	phrase = "No Content";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
	evhttp_clear_headers(&qheaders);
}

void
v1_network_list(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*respbuf = NULL;
	int			 code = HTTP_BADREQUEST;
	const char		*apikey;
	const char		*phrase = "Bad Request";
	char			*msg = NULL;

	if ((headers = evhttp_request_get_input_headers(req)) == NULL)
		goto cleanup;

	if ((apikey = evhttp_find_header(headers, "X-netvirt-apikey")) == NULL)
		goto cleanup;

	if (network_list(apikey, &msg) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0)
		goto cleanup;

	if ((respbuf = evbuffer_new()) == NULL)
		goto cleanup;

	if (evbuffer_add_reference(respbuf, msg, strlen(msg), NULL, NULL) < 0)
		goto cleanup;

	code = HTTP_OK;
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
	free(msg);
}

void
v1_network_cb(struct evhttp_request *req, void *arg)
{
	if (evhttp_request_get_command(req) == EVHTTP_REQ_GET)
		v1_network_list(req, arg);
	else if (evhttp_request_get_command(req) == EVHTTP_REQ_POST)
		v1_network_create(req, arg);
	else if (evhttp_request_get_command(req) == EVHTTP_REQ_DELETE)
		v1_network_delete(req, arg);
	else
		evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", NULL);
}

void
v1_node_create(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	int			 code = HTTP_BADREQUEST;
	const char		*apikey;
	const char		*type;
	const char		*phrase = "Bad Request";
	void			*p;

	if ((headers = evhttp_request_get_input_headers(req)) == NULL)
		goto cleanup;

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if ((apikey = evhttp_find_header(headers, "X-netvirt-apikey")) == NULL)
		goto cleanup;

	if (node_create(p, apikey) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	code = 201;
	phrase = "Created";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_node_delete(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	 qheaders = TAILQ_HEAD_INITIALIZER(qheaders);
	struct evkeyvalq	*headers;
	const struct evhttp_uri	*uri;
	int			 code = HTTP_BADREQUEST;
	const char		*apikey;
	const char		*phrase = "Bad Request";
	const char		*uid;
	const char		*query;

	if ((headers = evhttp_request_get_input_headers(req)) == NULL)
		goto cleanup;

	if ((apikey = evhttp_find_header(headers, "X-netvirt-apikey")) == NULL)
		goto cleanup;

	if ((uri = evhttp_request_get_evhttp_uri(req)) == NULL)
		goto cleanup;

	if ((query = evhttp_uri_get_query(uri)) == NULL)
		goto cleanup;

	if (evhttp_parse_query_str(query, &qheaders) < 0)
		goto cleanup;

	if ((uid = evhttp_find_header(&qheaders, "uid")) == NULL)
		goto cleanup;

	if (node_delete(uid, apikey) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	code = 204;
	phrase = "No Content";

cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
	evhttp_clear_headers(&qheaders);
}

void
v1_node_list(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	 qheaders = TAILQ_HEAD_INITIALIZER(qheaders);
	struct evkeyvalq	*headers;
	struct evbuffer		*respbuf = NULL;
	const struct evhttp_uri	*uri;
	int			 code = HTTP_BADREQUEST;
	const char		*apikey;
	const char		*phrase = "Bad Request";
	const char		*query;
	const char		*network_uid;
	char			*msg = NULL;

	if ((headers = evhttp_request_get_input_headers(req)) == NULL)
		goto cleanup;

	if ((apikey = evhttp_find_header(headers, "X-netvirt-apikey")) == NULL)
		goto cleanup;

	if ((uri = evhttp_request_get_evhttp_uri(req)) == NULL)
		goto cleanup;

	if ((query = evhttp_uri_get_query(uri)) == NULL)
		goto cleanup;

	if (evhttp_parse_query_str(query, &qheaders) < 0)
		goto cleanup;

	if ((network_uid = evhttp_find_header(&qheaders, "network_uid"))
	    == NULL)
		goto cleanup;

	if (node_list(network_uid, apikey, &msg) == -1) {
		code = 403;
		phrase = "Forbidden";
		goto cleanup;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0)
		goto cleanup;

	if ((respbuf = evbuffer_new()) == NULL)
		goto cleanup;

	if (evbuffer_add_reference(respbuf, msg, strlen(msg), NULL, NULL) < 0)
		goto cleanup;

	code = HTTP_OK;
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
	evhttp_clear_headers(&qheaders);
	free(msg);
}

void
v1_node_cb(struct evhttp_request *req, void *arg)
{
	if (evhttp_request_get_command(req) == EVHTTP_REQ_GET)
		v1_node_list(req, arg);
	else if (evhttp_request_get_command(req) == EVHTTP_REQ_POST)
		v1_node_create(req, arg);
	else if (evhttp_request_get_command(req) == EVHTTP_REQ_DELETE)
		v1_node_delete(req, arg);
	else
		evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", NULL);
}

void
v1_provisioning_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;
	struct evbuffer		*respbuf = NULL;
	int			 code = HTTP_BADREQUEST;
	const char		*type;
	const char		*phrase = "Bad Request";
	char			*msg = NULL;
	void			*p;

	if ((headers = evhttp_request_get_input_headers(req)) == NULL)
		goto cleanup;

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	if (node_provisioning(p, &msg) < 0)
		goto cleanup;

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0)
		goto cleanup;

	if ((respbuf = evbuffer_new()) == NULL)
		goto cleanup;

	if (evbuffer_add_reference(respbuf, msg, strlen(msg), NULL, NULL) < 0)
		goto cleanup;

	code = HTTP_OK;
	phrase = "OK";

cleanup:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
	free(msg);
}

int
restapi_init(json_t *config, struct event_base *evbase)
{
	struct evhttp			*http = NULL;
	struct evhttp_bound_socket	*handle;

	if ((http = evhttp_new(evbase)) == NULL)
		errx(1, "evhttp_new");

	if (evhttp_set_cb(http, "/v1/client", v1_client_create_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/client");

	if (evhttp_set_cb(http, "/v1/client/activate",
	    v1_client_activate_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/client/activate");

	if (evhttp_set_cb(http, "/v1/client/newapikey",
	    v1_client_get_newapikey_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/client/newapikey");

	if (evhttp_set_cb(http, "/v1/client/newresetkey",
	    v1_client_get_newresetkey_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/client/newresetkey");

	if (evhttp_set_cb(http, "/v1/client/password",
	    v1_client_update_password_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/client/password");

	if (evhttp_set_cb(http, "/v1/network", v1_network_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/network");

	if (evhttp_set_cb(http, "/v1/node", v1_node_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/node");

	if (evhttp_set_cb(http, "/v1/provisioning",
	    v1_provisioning_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/provisioning");

	if ((handle = evhttp_bind_socket_with_handle(http,
	    "0.0.0.0", 8080)) == NULL)
		errx(1, "evhttp_bind_socket_with_handle");

	return (0);
}
