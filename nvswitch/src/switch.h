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

#ifndef SWITCH_H
#define SWITCH_H

#include <sys/tree.h>

#include <event2/event.h>
#include <jansson.h>

#include <pki.h>

struct switch_config {

	const char	*log_file;

	const char	*switch_ip;
	const char	*switch_port;

	const char	*control_ip;
	const char	*control_port;
	const char	*certificate;
	const char	*privatekey;
	const char	*trustedcert;
};

struct vnetwork;

void		 vnetwork_free(struct vnetwork *);
struct vnetwork	*vnetwork_lookup(const char *);
void		 vnetworks_free(void);
int		 vnetwork_create(char *, char *, char *, char *);
int		 vnetwork_init(void);
int		 vnetwork_add_node(struct vnetwork *, const char *);
void		 vnetwork_del_node(struct vnetwork *, const char *);
struct node	*vnetwork_find_node(struct vnetwork *, const char *);

void		 switch_init(json_t *);
void		 switch_fini(void);

void		 control_init(void);
void		 control_fini(void);

extern json_t			*config;
extern struct event_base	*ev_base;
extern int			 control_init_done;

#endif
