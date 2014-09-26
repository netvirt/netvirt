/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "session.h"

void *session_itemdup(const void *item)
{
	return (void *)item;
}

void session_itemrel(void *item)
{
	struct session *session;
	if (item != NULL) {
		session = (struct session *)item;
		session->netc->on_disconnect = NULL;
		net_disconnect(session->netc);
		free(session);
	}
}
