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

#ifndef VNETWORK_H
#define VNETWORK_H

#include <ftable.h>
#include <pki.h>

#include "ctable.h"
#include "linkst.h"
#include "switch.h"
#include "tree.h"
#include "queue.h"

#define MAX_NODE 1024	// the maximum of nodes per context
#define TIMEOUT_SEC 300	// linkstate timeout in second

struct session {
	LIST_ENTRY(session) entry;
	struct mac_list	*mac_list;
	struct vnetwork	*vnetwork;
	uint8_t	  	 state;
	uint8_t		 tun_macaddr[6];
	uint8_t		 macaddr[6];
	char		*ip;
	char		*certname;
	char		 localip[16];
};

LIST_HEAD(session_list, session);

struct vnetwork {
	RB_ENTRY(vnetwork)	 entry;
	struct session_list	 sessions;
	ftable_t		*ftable;			// forwarding table
	ctable_t		*ctable;			// connection table
	ctable_t		*atable;			// access table
	linkst_t		*linkst;			// link state between nodes
	 //struct session          *access_session;                // store the access session in the access table for every known UUID
	passport_t		*passport;
	char			*uuid;
	uint32_t		 active_node;			// number of connected node
};

void vnetworks_free();
void vnetwork_free(struct vnetwork *);
void vnetwork_del_session(struct vnetwork *, struct session *);
void vnetwork_add_session(struct vnetwork *, struct session *);
struct vnetwork *vnetwork_disable(const char *);
struct vnetwork *vnetwork_lookup(const char *);
struct vnetwork *vnetwork_lookup_id(const char *id);
int vnetwork_create(char *, char *, char *, char *, char *, char *, char *);
void vnetwork_fini(void *);
int vnetwork_init();

#endif
