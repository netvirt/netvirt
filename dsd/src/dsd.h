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

#ifndef DSD_H
#define DSD_H

#include <netbus.h>

#define SESSION_STATE_AUTHED           0x1
#define SESSION_STATE_NOT_AUTHED       0x2

struct dsd_cfg {

	const char *ipaddr;
	const char *port;

	const char *db_host;
	const char *db_user;
	const char *db_pwd;
	const char *db_name;

	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;
};

netc_t *g_dnd_netc;
struct session {

	netc_t *netc;
	uint32_t timeout_id;
	uint8_t state;
};

extern int dsd_init(char *liste_addr, char *port, char *certificate, char *privatekey, char *trusted_authority);

#endif
