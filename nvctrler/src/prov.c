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

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>

#include <jansson.h>

#include <string.h>
#include <err.h>

void
v1_prov_cb(struct evhttp_request *req, void *arg)
{
	void			*p;
	const char		*type;
	const char		*phrase = "Bad Request";
	int			 code = HTTP_BADREQUEST;
	struct evkeyvalq	*headers;
	struct evbuffer		*buf;

	headers = evhttp_request_get_input_headers(req);

	if ((type = evhttp_find_header(headers, "Content-Type")) == NULL ||
		strncmp(type, "application/json", 16) != 0)
		goto cleanup;

	buf = evhttp_request_get_input_buffer(req);
	evbuffer_add(buf, "\0", 1);
	if ((p = evbuffer_pullup(buf, -1)) == NULL)
		goto cleanup;

	code = HTTP_OK;
	phrase = "OK";
cleanup:
	evhttp_send_reply(req, code, phrase, NULL);
}

int
prov_init(json_t *config, struct event_base *evbase)
{
	struct evhttp			*http = NULL;
	struct evhttp_bound_socket	*handle;

	if ((http = evhttp_new(evbase)) == NULL)
		errx(1, "evhttp_new");

	evhttp_set_allowed_methods(http, EVHTTP_REQ_POST);

	if (evhttp_set_cb(http, "/v1/prov", v1_prov_cb, NULL) < 0)
		errx(1, "evhttp_set_cb /v1/prov");


	if ((handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", 8080)) == NULL)
		errx(1, "evhttp_bind_socket_with_handle");

	return 0;
}
