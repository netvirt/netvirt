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

#ifndef REQUEST_H
#define REQUEST_H

#include <jansson.h>
#include <dnds.h>
#include "ctrler.h"

void update_node_status(struct session_info *, json_t *);
void del_network(struct session_info *, json_t *);
void add_node(struct session_info *, json_t *);
void del_node(struct session_info *, json_t *);
void provisioning(struct session_info *, json_t *);
void listall_network(struct session_info *, json_t *);
void listall_node(struct session_info *, json_t *);
void activate_account(struct session_info *, json_t *);
void add_account(struct session_info *, json_t *);
void get_account_apikey(struct session_info *, json_t *);
void add_network(struct session_info *, json_t *);
void list_network(struct session_info *, json_t *);
void list_node(struct session_info *, json_t *);

#endif
