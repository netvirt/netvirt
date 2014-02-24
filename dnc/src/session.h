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

#include <netbus.h>
#include <tapcfg.h>

#define	SESSION_STATE_AUTHED		0x01
#define SESSION_STATE_NOT_AUTHED	0x02
#define SESSION_STATE_WAIT_ANSWER	0x04
#define SESSION_STATE_DOWN		0x08

#define SESSION_TYPE_CLIENT		0x01
#define SESSION_TYPE_SERVER		0x02
#define SESSION_TYPE_P2P_CLIENT		0x03
#define SESSION_TYPE_P2P_SERVER		0x04

struct session {
	passport_t *passport;
	netc_t *netc;
	tapcfg_t *tapcfg;
	const char *devname;
	uint8_t mac_dst[ETHER_ADDR_LEN];
	char state;
	char type;
};

void *session_itemdup(const void *item);
void session_itemrel(void *item);

#endif
