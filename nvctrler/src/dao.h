/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#include <sys/types.h>

int dao_init(const char *, const char *, const char *, const char *);
void dao_fini();
void dao_reset_node_state();

int dao_client_create(char *, char *, char *);
int dao_client_activate(char *);
int dao_client_update_apikey(char *, char *);
int dao_client_update_apikey2(char *, char *, char *);
int dao_client_update_resetkey(char *, char *);
int dao_client_update_password(char *, char *, char *);
int dao_client_get_id(char **, const char *);

int dao_network_create(char *, char *, char *, char *, char *, char *, char *, char *,
    char *, char *, const unsigned char *, size_t);
int dao_network_delete(char **, const char *, const char *);
int dao_network_list(const char *, int (*)(const char *, const char *, void *),
    void *);
int dao_network_update_ippool(const char *, uint8_t *, size_t);
int dao_network_update_serial(const char *, const char *);

//int dao_network_update();
int dao_network_get_embassy(const char *, char **, char **, char **);
int dao_network_get_ippool(const char *, char **, char **, char **, uint8_t **);

int dao_node_create(const char *, const char *, const char *, const char *,
    const char *);
int dao_node_delete(char **, const char *, const char *);
int dao_update_node_status(char *, char *, char *, char *);
int dao_node_list(const char *, const char *, int (*)(const char *,
    const char *, const char *, const char *, const char *, void *), void *);
int dao_node_update();
int dao_node_delete_provkey(const char *, const char *, const char *);
int dao_node_netinfo(const char *, const char *,
    char **, char **, char **, char **, uint8_t **);

int dao_node_listall(void *,
    int (*cb)(void *, int, const char *, const char *, const char *, const char *));
int dao_switch_network_list(void *,
    int (*cb)(void *, int , const char *, const char *, const char *, const char *));

int dao_switch_node_list(void *,
    int (*cb)(void *, int, const char *, const char *));
#endif
