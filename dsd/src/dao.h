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

#ifndef DAO_H
#define DAO_H

#include "dsd.h"
int dao_connect(struct dsd_cfg *dsd_cfg);

/*int dao_fetch_context_by_client_id(char *client_id,
			char **id,
			char **topology_id,
			char **description,
			char **network,
			char **netmask,
			char **serverCert,
			char **serverPrivkey,
			char **trustedCert);

int dao_fetch_context(char **id,
			char **topology_id,
			char **description,
			char **network,
			char **netmask,
			char **serverCert,
			char **serverPrivkey,
			char **trustedCert);
*/
char *uuid_v4(void);
#endif
