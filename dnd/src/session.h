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

#ifndef SESSION_H
#define SESSION_H

#include <inttypes.h>

#include <cert.h>
#include <netbus.h>

#define SESSION_STATE_AUTHED           0x1
#define SESSION_STATE_NOT_AUTHED       0x2
#define SESSION_STATE_WAIT_STEPUP      0x4

struct mac_list {
	uint8_t mac_addr[6];
	struct mac_list *next;
};

struct session {

	uint8_t state;

	char *ip;
	char *cert_name;
	node_info_t *node_info;

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
void session_add_mac(struct session *session, uint8_t *mac_addr);

#endif
