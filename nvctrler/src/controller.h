/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <event2/event.h>

#include <jansson.h>

#define SESSION_AUTH		0x1
#define SESSION_NOT_AUTH	0x2

#define NVSWITCH		0x1


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

struct session_info {
	struct bufferevent	*bev;
	uint8_t			 type;
	uint8_t			 state;
	char			 cert_name[256];
};

extern json_t			*config;
extern struct event_base	*ev_base;

void controller_init(void);
void controller_fini(void);

int restapi_init(json_t *, struct event_base *);

#endif
