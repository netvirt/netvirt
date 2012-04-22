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

#ifndef DNC_SESSION_H
#define DNC_SESSION_H

#include <dnds/net.h>
#include <dnds/netbus.h>

#define	SESSION_STATUS_AUTHED		0x1
#define SESSION_STATUS_NOT_AUTHED	0x2
#define SESSION_STATUS_WAIT_ANSWER	0x4
#define SESSION_STATUS_DOWN		0x8

#define SESSION_TYPE_CLIENT		0x1
#define SESSION_TYPE_SERVER		0x2
#define SESSION_TYPE_P2P_CLIENT		0x3
#define SESSION_TYPE_P2P_SERVER		0x4

struct session {

	uint8_t status;
	uint8_t type;

	char ip_local[INET_ADDRSTRLEN];
	uint8_t tun_mac_addr[ETHER_ADDR_LEN];

	char *server_address;
	char *server_port;

	passport_t *passport;

	iface_t *iface;
	peer_t *peer;
	netc_t *netc;
};

void *session_itemdup(const void *item);
void session_itemrel(void *item);

#endif /* DNC_SESSION_H */
