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

#include <log.h>

#include "request.h"

void
cleanup_cb(const void *data, size_t datalen, void *extra)
{
	free((void*)data);
}

void
v1_regions_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer	*respbuf = NULL;
	int		 code;
	const char	*apikey;
	const char	*phrase;
	char		*msg;

	code = 500;
	phrase = "Internal Server Error";

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
		log_warnx("%s: evhttp_request_get_command", __func__);
		goto out;
	}

	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if (regions_list(apikey, &msg) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: regions_list", __func__);
		goto out;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0) {
		log_warnx("%s: evhttp_add_header", __func__);
		goto out;
	}

	if ((respbuf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto out;
	}

	if (evbuffer_add_reference(respbuf, msg, strlen(msg),
	    cleanup_cb, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto out;
	}

	code = HTTP_OK;
	phrase = "OK";
out:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
}

void
v1_client_create_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer		*buf;
	int			 code;
	const char		*type;
	const char		*phrase;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		log_warnx("%s: evhttp_request_get_command", __func__);
		goto out;
	}

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto out;
	}

	if (client_create(p) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: client_create", __func__);
		goto out;
	}

	code = 201;
	phrase = "Created";

out:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_client_activate_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer		*buf;
	int			 code;
	const char		*type;
	const char		*phrase;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		log_warnx("%s: evhttp_request_get_command", __func__);
		goto out;
	}

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto out;
	}

	if (client_activate(p) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: client_active", __func__);
		goto out;
	}

	code = 200;
	phrase = "OK";

out:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_client_get_newapikey_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer		*buf;
	struct evbuffer		*respbuf = NULL;
	int			 code;
	const char		*type;
	const char		*phrase;
	char			*msg;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		log_warnx("%s: evhttp_request_get_command", __func__);
		goto out;
	}

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto out;
	}

	if (client_get_newapikey(p, &msg) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: client_get_newapikey", __func__);
		goto out;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0) {
		log_warnx("%s: evhttp_add_header", __func__);
		goto out;
	}

	if ((respbuf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto out;
	}

	if (evbuffer_add_reference(respbuf, msg, strlen(msg),
	    cleanup_cb, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto out;
	}

	code = HTTP_OK;
	phrase = "OK";

out:
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
	int			 code;
	const char		*type;
	const char		*phrase;
	char			*msg;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		log_warnx("%s: evhttp_request_get_command", __func__);
		goto cleanup;
	}

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto cleanup;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto cleanup;
	}

	if (client_get_newresetkey(p, &msg) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: client_get_newresetkey", __func__);
		goto cleanup;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0) {
		log_warnx("%s: evhttp_add_header", __func__);
		goto cleanup;
	}

	if ((respbuf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto cleanup;
	}

	if (evbuffer_add_reference(respbuf, msg, strlen(msg),
	    cleanup_cb, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto cleanup;
	}

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
	struct evbuffer		*buf;
	int			 code;
	const char		*type;
	const char		*phrase;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		log_warnx("%s: evhttp_request_get_command", __func__);
		goto out;
	}

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto out;
	}

	if (client_reset_password(p) < 0) {
		code = 403;
		phrase = "Forbidden"; 
		log_warnx("%s: client_reset_password", __func__);
		goto out;
	}

	code = HTTP_OK;
	phrase = "OK";

out:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_network_create(struct evhttp_request *req, void *arg)
{
	struct evbuffer		*buf;
	int			 code;
	const char		*apikey;
	const char		*type;
	const char		*phrase;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto out;
	}


	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if (network_create(p, apikey) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: network_create", __func__);
		goto out;
	}

	code = 201;
	phrase = "Created";

out:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_network_delete(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	 qheaders = TAILQ_HEAD_INITIALIZER(qheaders);
	int			 code;
	const char		*apikey;
	const char		*phrase;
	const char		*description;

	code = 500;
	phrase = "Internal Server Error";

	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if (evhttp_parse_query_str(evhttp_uri_get_query(
	    evhttp_request_get_evhttp_uri(req)), &qheaders) < 0) {
		log_warnx("%s: evhttp_parse_query_str", __func__);
		goto out;
	}

	if ((description = evhttp_find_header(&qheaders,
	    "description")) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if (network_delete(description, apikey) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: network_delete", __func__);
		goto out;
	}

	code = 204;
	phrase = "No Content";

out:
	evhttp_send_reply(req, code, phrase, NULL);
	evhttp_clear_headers(&qheaders);
}

void
v1_network_list(struct evhttp_request *req, void *arg)
{
	struct evbuffer		*respbuf = NULL;
	int			 code;
	const char		*apikey;
	const char		*phrase;
	char			*msg;

	code = 500;
	phrase = "Internal Server Error";

	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if (network_list(apikey, &msg) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: network_list", __func__);
		goto out;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0) {
		log_warnx("%s: evhttp_add_header", __func__);
		goto out;
	}

	if ((respbuf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto out;
	}

	if (evbuffer_add_reference(respbuf, msg, strlen(msg),
	    cleanup_cb, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto out;
	}

	code = HTTP_OK;
	phrase = "OK";

out:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
}

void
v1_network_cb(struct evhttp_request *req, void *arg)
{
	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}

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
	struct evbuffer		*buf;
	int			 code;
	const char		*apikey;
	const char		*type;
	const char		*phrase;
	void			*p;

	code = 500;
	phrase = "Internal server error";

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header x-netvirt-apikey", __func__);
		goto out;
	}

	if (node_create(p, apikey) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: node_create", __func__);
		goto out;
	}

	code = 201;
	phrase = "Created";

out:
	evhttp_send_reply(req, code, phrase, NULL);
}

void
v1_node_delete(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	 qheaders = TAILQ_HEAD_INITIALIZER(qheaders);
	int			 code;
	const char		*apikey;
	const char		*phrase;
	const char		*description;

	code = 500;
	phrase = "Internal Server Error";

	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header X-netvirt-apikey", __func__);
		goto out;
	}

	if (evhttp_parse_query_str(evhttp_uri_get_query(
	    evhttp_request_get_evhttp_uri(req)), &qheaders) < 0) {
		log_warnx("%s: evhttp_parse_query_str", __func__);
		goto out;
	}

	if ((description = evhttp_find_header(&qheaders,
	    "description")) == NULL) {
		log_warnx("%s: evhttp_find_header description", __func__);
		goto out;
	}

	if (node_delete(description, apikey) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: node_delete", __func__);
		goto out;
	}

	code = 204;
	phrase = "No Content";

out:
	evhttp_send_reply(req, code, phrase, NULL);
	evhttp_clear_headers(&qheaders);
}

void
v1_node_list(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq	 qheaders = TAILQ_HEAD_INITIALIZER(qheaders);
	struct evbuffer		*respbuf = NULL;
	const struct evhttp_uri	*uri;
	int			 code;
	const char		*apikey;
	const char		*phrase;
	const char		*query;
	const char		*network_uid;
	char			*msg;

	code = 500;
	phrase = "Internal server error";

	if ((apikey = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "X-netvirt-apikey")) == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if ((uri = evhttp_request_get_evhttp_uri(req)) == NULL) {
		log_warnx("%s: evhttp_request_get_evhttp_uri", __func__);
		goto out;
	}

	if ((query = evhttp_uri_get_query(uri)) == NULL) {
		log_warnx("%s: evhttp_uri_get_query", __func__);
		goto out;
	}

	if (evhttp_parse_query_str(query, &qheaders) < 0) {
		log_warnx("%s: evhttp_parse_query", __func__);
		goto out;
	}

	if ((network_uid = evhttp_find_header(&qheaders, "network_uid"))
	    == NULL) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	if (node_list(network_uid, apikey, &msg) < 0) {
		code = 403;
		phrase = "Forbidden";
		log_warnx("%s: node_list", __func__);
		goto out;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0) {
		log_warnx("%s: evhttp_add_header", __func__);
		goto out;
	}

	if ((respbuf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto out;
	}

	if (evbuffer_add_reference(respbuf, msg, strlen(msg),
	    cleanup_cb, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto out;
	}

	code = HTTP_OK;
	phrase = "OK";

out:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
	evhttp_clear_headers(&qheaders);
}

void
v1_node_cb(struct evhttp_request *req, void *arg)
{
	if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
		evhttp_send_reply(req, 200, "OK", NULL);
		return;
	}
	else if (evhttp_request_get_command(req) == EVHTTP_REQ_GET)
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
	struct evbuffer		*buf;
	struct evbuffer		*respbuf = NULL;
	int			 code;
	const char		*type;
	const char		*phrase;
	char			*msg;
	void			*p;

	code = 500;
	phrase = "Internal Server Error";

	if ((type = evhttp_find_header(evhttp_request_get_input_headers(req),
	    "Content-Type")) == NULL ||
	    strncasecmp(type, "application/json", 16) != 0) {
		log_warnx("%s: evhttp_find_header", __func__);
		goto out;
	}

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL) {
		log_warnx("%s: evbuffer_pullup", __func__);
		goto out;
	}

	if (node_provisioning(p, &msg) < 0) {
		log_warnx("%s: node_provisioning", __func__);
		goto out;
	}

	if (evhttp_add_header(req->output_headers, "Content-Type",
	    "application/json") < 0) {
		log_warnx("%s: evhttp_add_header", __func__);
		goto out;
	}

	if ((respbuf = evbuffer_new()) == NULL) {
		log_warnx("%s: evbuffer_new", __func__);
		goto out;
	}

	if (evbuffer_add_reference(respbuf, msg, strlen(msg),
	    cleanup_cb, NULL) < 0) {
		log_warnx("%s: evbuffer_add_reference", __func__);
		goto out;
	}
	code = HTTP_OK;
	phrase = "OK";

out:
	evhttp_send_reply(req, code, phrase, respbuf);
	if (respbuf != NULL)
		evbuffer_free(respbuf);
}

int
restapi_init(json_t *config, struct event_base *evbase)
{
	struct evhttp			*http;
	struct evhttp_bound_socket	*handle;

	if ((http = evhttp_new(evbase)) == NULL)
		errx(1, "evhttp_new");

	evhttp_set_allowed_methods(http, EVHTTP_REQ_GET | EVHTTP_REQ_POST |
	    EVHTTP_REQ_DELETE | EVHTTP_REQ_OPTIONS);

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

	if (evhttp_set_cb(http, "/v1/regions",
	    v1_regions_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/regions");

	if ((handle = evhttp_bind_socket_with_handle(http,
	    "0.0.0.0", 8080)) == NULL)
		errx(1, "evhttp_bind_socket_with_handle");

	return (0);
}
