/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifndef DNDS_DSD_H
#define DNDS_DSD_H

#include <net.h>

#define SESSION_STATUS_AUTHED           0x1
#define SESSION_STATUS_NOT_AUTHED       0x2

struct session {

	uint8_t status;

	netc_t *netc;
	uint32_t timeout_id;
};

extern int dsd_init(char *liste_addr, char *port, char *certificate, char *privatekey, char *trusted_authority);

#endif
