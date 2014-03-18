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
