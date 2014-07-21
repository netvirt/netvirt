/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#ifndef DNC_H
#define DNC_H

#include <netbus.h>

struct dnc_cfg {
	const char *server_address;
	const char *server_port;
	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;
	char *prov_code;
	const char *log_file;
	int auto_connect;

	const char *dnc_conf;
	const char *ip_conf;

	struct {
		void (*on_log)(const char *str);
		void (*on_connect)(const char *ip);
		void (*on_disconnect)();
	} ev;
};

#ifdef __cplusplus
extern "C" {
#endif

void dnc_init_async(struct dnc_cfg *cfg);
void *dnc_init(void *dnc_cfg);
int dnc_config_toggle_auto_connect(int status);
void on_input(netc_t *netc);

#ifdef __cplusplus
}
#endif

#endif
