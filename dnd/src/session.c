/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#include <logger.h>
#include "session.h"

struct session *session_new()
{
	struct session *session = NULL;

	session = calloc(1, sizeof(struct session));
	if (session == NULL) {
		jlog(L_ERROR, "memory allocation failed");
		return NULL;
	}

	session->state = SESSION_STATE_NOT_AUTHED;

	return session;
}

void session_free(struct session *session)
{
	if (session == NULL) {
		return;
	}

	if (session->ip != NULL) {
		free(session->ip);
		session->ip = NULL;
	}

	if (session->cert_name != NULL) {
		free(session->cert_name);
		session->cert_name = NULL;
	}

	if (session->node_info) {
		node_info_destroy(session->node_info);
	}

	free(session);
}

void session_add_mac(struct session *session, uint8_t *mac_addr)
{
	struct mac_list *mac_list = NULL;
	mac_list = calloc(1, sizeof(struct mac_list));
	memcpy(mac_list->mac_addr, mac_addr, ETHER_ADDR_LEN);

	if (session->mac_list == NULL) {
		session->mac_list = mac_list;
	} else {
		mac_list->next = session->mac_list;
		session->mac_list = mac_list;
	}
}

void session_terminate(struct session *session)
{
	jlog(L_NOTICE, "terminating session");
	net_disconnect(session->netc);
	session_free(session);
}

void *session_itemdup(const void *item)
{
	struct session *session;
	session = calloc(1, sizeof(struct session));

	memmove(session, item, sizeof(struct session));

	return session;
}

void session_itemrel(void *item)
{
	struct session *session;
	if (item != NULL) {
		session = (struct session *)item;
		free(session);
	}
}
