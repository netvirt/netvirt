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

#ifndef DSC_H
#define DSC_H

#include <dnds.h>

int transmit_provisioning(struct session *session, char *provCode, uint32_t length);
int transmit_peerconnectinfo(e_ConnectState state, char *ipAddress, char *certName);
int dsc_init(struct dnd_cfg *cfg);

#endif
