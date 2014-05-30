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

#ifndef DSD_H
#define DSD_H

#include <netbus.h>

#define SESSION_STATE_AUTHED           0x1
#define SESSION_STATE_NOT_AUTHED       0x2

struct dsd_cfg {

	const char *log_file;

	const char *ipaddr;
	const char *port;

	const char *db_host;
	const char *db_user;
	const char *db_pwd;
	const char *db_name;

	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;

	int dsd_running;
};

netc_t *g_dnd_netc;
struct session {

	netc_t *netc;
	uint32_t timeout_id;
	uint8_t state;
};

int dsd_init(struct dsd_cfg *cfg);
void dsd_fini();

#endif
