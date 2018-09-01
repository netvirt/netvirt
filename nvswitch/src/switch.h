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
struct node;

void		 switch_init(json_t *);
void		 switch_fini(void);
struct vnetwork	*vnetwork_find(const char *);
void		 vnetwork_del(struct vnetwork *);
int		 vnetwork_add(char *, char *, char *, char *);
struct node	*vnetwork_find_node(struct vnetwork *, const char *);
void		 vnetwork_del_node(struct vnetwork *, struct node *);
int		 vnetwork_add_node(struct vnetwork *, const char *);

void		 control_init(void);
void		 control_fini(void);
int		 request_update_node_status(char *, char *, char *, char *);

extern json_t			*config;
extern struct event_base	*ev_base;
extern int			 control_init_done;

#endif
