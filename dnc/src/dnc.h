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

#ifndef DNC_H
#define DNC_H

struct dnc_cfg {
	const char *server_address;
	const char *server_port;
	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;
	char *prov_code;

	struct {
		void (*on_connect)(void *);
		void *obj;
	} ev;
};

#ifdef __cplusplus
extern "C" {
#endif

int dnc_init(struct dnc_cfg *dnc_cfg);

#ifdef __cplusplus
}
#endif

#endif
