/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
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

#ifndef CTRLER_H
#define CTRLER_H

#include <netbus.h>

#define SESSION_STATE_AUTHED           0x1
#define SESSION_STATE_NOT_AUTHED       0x2

struct ctrler_cfg {

	const char *log_file;

	const char *listen_ip;
	const char *listen_port;

	const char *db_host;
	const char *db_user;
	const char *db_pwd;
	const char *db_name;

	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;

	int ctrler_running;
};

netc_t *g_switch_netc;
struct session {

	netc_t *netc;
	uint32_t timeout_id;
	uint8_t state;
};

int ctrler_init(struct ctrler_cfg *cfg);
void ctrler_fini();

#endif
