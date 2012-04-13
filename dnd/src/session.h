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

#ifndef DND_SESSION_H
#define DND_SESSION_H

#include <dnds/net.h>
#include "context.h"

#define SESSION_STATUS_AUTHED           0x1
#define SESSION_STATUS_NOT_AUTHED       0x2
#define SESSION_STATUS_WAIT_STEPUP      0x4

struct session {

	uint8_t status;

	char *ip;	/* Client tunnel IP address */
	char *cert_name;

	uint32_t id;
	char ip_local[INET_ADDRSTRLEN];
	uint8_t tun_mac_addr[ETHER_ADDR_LEN];

	netc_t *netc;
	struct context *context;

	/* should we support a mac list XXX */
	uint8_t mac_addr[ETHER_ADDR_LEN];

	struct session *next;
	struct session *prev;

};

struct session *session_new();
void session_free(struct session *session);
void session_terminate(struct session *session);
void *session_itemdup(const void *item);
void session_itemrel(void *item);

#endif
