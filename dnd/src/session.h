/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifndef SESSION_H
#define SESSION_H

#include <inttypes.h>
#include "netbus.h"

#define SESSION_STATUS_AUTHED           0x1
#define SESSION_STATUS_NOT_AUTHED       0x2
#define SESSION_STATUS_WAIT_STEPUP      0x4

struct mac_list {
	uint8_t mac_addr[6];
	struct mac_list *next;
};

struct session {

	uint8_t status;

	char *ip;
	char *cert_name;

	uint32_t id;
	char ip_local[16];
	uint8_t tun_mac_addr[6];

	netc_t *netc;
	struct context *context;

	uint8_t mac_addr[6];
	struct mac_list *mac_list;

	struct session *next;
	struct session *prev;

};

struct session *session_new();
void session_free(struct session *session);
void session_terminate(struct session *session);
void *session_itemdup(const void *item);
void session_itemrel(void *item);

#endif
