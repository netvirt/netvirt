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

#include "session.h"

void *session_itemdup(const void *item)
{
	dn_sess_t *sess;
	sess = calloc(1, sizeof(dn_sess_t));

	memcpy(sess, item, sizeof(dn_sess_t));

	return sess;
}

void session_itemrel(void *item)
{
	dn_sess_t *session;

	if (item != NULL) {
		session = (dn_sess_t *)item;
		free(session);
	}
}
