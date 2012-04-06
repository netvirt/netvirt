/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds/journal.h>
#include "session.h"

struct session *session_new()
{
	struct session *session = NULL;

	session = calloc(1, sizeof(struct session));
	if (session == NULL) {
		JOURNAL_CRIT("dnd]> memory allocation failed");
		return NULL;
	}

	session->next = NULL;
	session->prev = NULL;
	session->context = NULL;

	session->status = SESSION_STATUS_NOT_AUTHED;

	return session;
}

void session_free(struct session*session)
{
	if (session == NULL) {
		return;
	}

	if (session->ip != NULL) {
		free(session->ip);
	}
	
	free(session);
}

void session_terminate(struct session *session)
{
	JOURNAL_INFO("dnd]> terminating session");
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
