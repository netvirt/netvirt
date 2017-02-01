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

#ifndef DAO_H
#define DAO_H

#include "ctrler.h"

int dao_init(const char *, const char *, const char *, const char *);
void dao_fini();

int dao_client_create(char *, char *, char *);
int dao_client_activate(char *);
int dao_client_update_apikey(char *, char *);
int dao_client_update_apikey2(char *, char *, char *);
int dao_client_update_resetkey(char *, char *);
int dao_client_update_password(char *, char *, char *);
int dao_client_get_id(char **, const char *);

int dao_network_create(char *, char *, char *, char *, char *, char *, char *, char *, char *, const unsigned char *, size_t);
int dao_network_delete(const char *, const char *);
int dao_network_list(const char *, int (*)(const char *, const char *, void *), void *);
int dao_network_update();

int dao_node_create();
int dao_node_delete();
int dao_node_list();
int dao_node_update();

void dao_reset_node_state();
#endif
