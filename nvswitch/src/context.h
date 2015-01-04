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

#ifndef CONTEXT_H
#define CONTEXT_H

#include <crypto.h>
#include <ftable.h>
#include <netbus.h>
#include <mbuf.h>

#include "ctable.h"
#include "linkst.h"
#include "switch.h"

#define MAX_NODE 1024	// the maximum of nodes per context
#define TIMEOUT_SEC 300	// linkstate timeout in second

typedef struct context {

	uint32_t id;				// context unique identifier
	ftable_t *ftable;			// forwarding table
	ctable_t *ctable;			// connection table
	ctable_t *atable;			// access table

	uint32_t active_node;			// number of connected node
	linkst_t *linkst;			// link state between nodes
	uint8_t *bitpool;			// bitpool used to generated unique ID per session

	struct session *session_list;		// all active session in this context
	struct session *access_session;		// store the 'access_session' placeholder
						// in the access table for every known UUID as a marker

	passport_t *passport;

} context_t;

void context_add_session(context_t *ctx, struct session *session);
void context_del_session(context_t *ctx, struct session *session);

context_t *context_disable(uint32_t id);
context_t *context_lookup(uint32_t id);

int context_create(uint32_t id, char *address, char *netmask, char *serverCert, char *serverPrivkey, char *trustedCert);
void context_free(context_t *context);

void contexts_free();

void context_fini(void *ext_ptr);
int context_init();

#endif
