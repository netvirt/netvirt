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

#include "session.h"

void *session_itemdup(const void *item)
{
	struct session *session;

	session = calloc(1, sizeof(struct session));
	memcpy(session, item, sizeof(struct session));

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
