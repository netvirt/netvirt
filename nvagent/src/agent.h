/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
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

#ifndef AGENT_H
#define AGENT_H

#include <netbus.h>

struct agent_cfg {
	char *server_address;
	char *server_port;

	char *certificate;
	char *privatekey;
	char *trusted_cert;

	char *tmp_pvkey_pem;
	char *prov_code;
	const char *log_file;
	int auto_connect;

	char *profile;
	char *agent_conf;
	char *ip_conf;

	struct {
		void (*on_log)(const char *str);
		void (*on_connect)(const char *ip);
		void (*on_disconnect)();
	} ev;

	int agent_running;
};

#ifdef __cplusplus
extern "C" {
#endif

void agent_fini();
void agent_init_async(struct agent_cfg *cfg);
void *agent_init(void *agent_cfg);
int agent_config_toggle_auto_connect(int status);
void on_input(netc_t *netc);

#ifdef __cplusplus
}
#endif

#endif
