/*
 * session.c: Session API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds/journal.h>
#include "session.h"

session_t *session_new()
{
	session_t *session = NULL;

	session = (session_t *)calloc(1, sizeof(session_t));
	if (session == NULL) {
		JOURNAL_CRIT("dnd]> memory allocation failed");
		return NULL;
	}

	session->next = NULL;
	session->prev = NULL;
	session->context = NULL;

	session->auth = SESS_NOT_AUTHENTICATED;

	return session;
}

void session_free(session_t *session)
{
	if (session == NULL) {
		return;
	}

	if (session->ip != NULL) {
		free(session->ip);
	}
	
	free(session);
}

void session_terminate(session_t *session)
{
	JOURNAL_INFO("dnd]> terminating session");
	net_disconnect(session->netc);
	session_free(session);
}

void *session_itemdup(const void *item)
{
	session_t *session;
	session = calloc(1, sizeof(session_t));

	memmove(session, item, sizeof(session_t));

	return session;
}

void session_itemrel(void *item)
{
	session_t *session;
	if (item != NULL) {
		session = (session_t*)item;
		free(session);
	}
}
