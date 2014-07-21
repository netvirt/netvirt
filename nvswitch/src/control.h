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

#ifndef DSC_H
#define DSC_H

#include <dnds.h>

#include "session.h"
#include "switch.h"

int transmit_provisioning(struct session *session, char *provCode, uint32_t length);
int transmit_peerconnectinfo(e_ConnectState state, char *ipAddress, char *certName);
int transmit_node_connectinfo(e_ConnectState state, char *ipAddress, char *certName);
int dsc_init(struct switch_cfg *cfg);
void dsc_fini();

#endif
