/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#include "dnd.h"
#include "linkst.h"

#define MAX_NODE 1024				// the maximum of nodes per context

typedef struct context {

	int id;					// context unique identifier
	ftable_t *ftable;			// forwarding table

	uint32_t active_node;			// number of connected node
	linkst_t **linkst;			// linkstate adjacency matrix
	uint8_t *bitpool;			// bitpool used to generated unique ID per session

	struct session *session_list;		// all session open in this context

	passport_t *passport;

} context_t;

int context_create(uint32_t id, char *address, char *netmask,
			char *serverCert, char *serverPrivkey, char *trustedCert);
void context_del_session(context_t *ctx, struct session *session);
void context_add_session(context_t *ctx, struct session *session);
context_t *context_lookup(uint32_t id);

void context_fini(void *ext_ptr);
int context_init();

#endif
