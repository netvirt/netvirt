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

#ifndef DND_H
#define DND_H

#include "context.h"

struct dnd_cfg {

	const char *ipaddr;
	const char *port;

	const char *dsd_ipaddr;
	const char *dsd_port;

	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;
};

int dnd_init(struct dnd_cfg *dnd_cfg);

#endif
