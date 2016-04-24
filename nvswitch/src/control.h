/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
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

#ifndef CONTROL_H
#define CONTROL_H

#include <dnds.h>

#include "session.h"
#include "switch.h"

int query_provisioning(struct session *, char *);
int query_list_node();
int update_node_status(char *, char *, char *, char *);
int query_list_network();
int ctrl_init(struct switch_cfg *);
void ctrl_fini();

#endif
