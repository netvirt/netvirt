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

#ifndef VNETWORK_H
#define VNETWORK_H

#include <pki.h>

#include "switch.h"
#include "tree.h"
#include "queue.h"

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
//	ftable_t		*ftable;			// forwarding table
//	ctable_t		*ctable;			// connection table
//	ctable_t		*atable;			// access table
	passport_t		*passport;
	char			*uid;
	uint32_t		 active_node;			// number of connected node
};

void		 vnetwork_free(struct vnetwork *);
void		 vnetwork_del_session(struct vnetwork *, struct session *);
struct session	*vnetwork_add_session(struct vnetwork *);
struct vnetwork	*vnetwork_lookup(const char *);
void		 vnetworks_free(void);
int		 vnetwork_create(char *, char *, char *, char *);
int		 vnetwork_init(void);

#endif
