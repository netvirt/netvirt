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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <bitv.h>
#include <logger.h>
#include <crypto.h>
#include <netbus.h>

#include "hash.h"
#include "inet.h"
#include "session.h"
#include "tree.h"
#include "vnetwork.h"

/// uuid
RB_HEAD(vnetwork_tree, vnetwork);
static struct vnetwork_tree	vnetworks;

static int vnetwork_cmp(const struct vnetwork *, const struct vnetwork *);
RB_PROTOTYPE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);

static int vnetwork_cmp(const struct vnetwork *a, const struct vnetwork *b)
{
	return strcmp(a->uuid, b->uuid);
}

/// id
RB_HEAD(vnetwork_tree_id, vnetwork);
static struct vnetwork_tree_id	vnetworks_id;

static int vnetwork_cmp_id(const struct vnetwork *, const struct vnetwork *);
RB_PROTOTYPE_STATIC(vnetwork_tree_id, vnetwork, entry_id, vnetwork_cmp_id);

static int vnetwork_cmp_id(const struct vnetwork *a, const struct vnetwork *b)
{
	return strcmp(a->id, b->id);
}

void vnetwork_del_session(struct vnetwork *vnet, struct session *session)
{
	if (session->next == NULL) {
		if (session->prev == NULL)
			vnet->session_list = NULL;
		else
			session->prev->next = NULL;
	} else {
		if (session->prev == NULL) {
			vnet->session_list = session->next;
			session->next->prev = NULL;
		}
		else {
			session->prev->next = session->next;
			session->next->prev = session->prev;
		}
	}

	bitpool_release_bit(vnet->bitpool, MAX_NODE, session->id-1);
	vnet->active_node--;
}

void vnetwork_add_session(struct vnetwork *vnet, struct session *session)
{
	if (vnet->session_list == NULL) {
		vnet->session_list = session;
		vnet->session_list->next = NULL;
		vnet->session_list->prev = NULL;
	}
	else {
		session->next = vnet->session_list;
		vnet->session_list->prev = session;
		vnet->session_list = session;
	}

	bitpool_allocate_bit(vnet->bitpool, MAX_NODE, &session->id);
	session->id+=1;
	vnet->active_node++;
}

void vnetwork_show_session_list(struct vnetwork *vnet)
{
	struct session *itr = NULL;
	itr = vnet->session_list;

	while (itr != NULL) {
		jlog(L_DEBUG, "session: %p:%s\n", itr, itr->ip);
		itr = itr->next;
	}
	jlog(L_DEBUG, "--\n");
}

struct vnetwork *vnetwork_lookup(const char *uuid)
{
	struct vnetwork match;

	match.uuid = (char *)uuid;
	return RB_FIND(vnetwork_tree, &vnetworks, &match);
}

struct vnetwork *vnetwork_lookup_id(const char *id)
{
	struct vnetwork match;

	match.id = (char *)id;
	return RB_FIND(vnetwork_tree_id, &vnetworks_id, &match);
}

void vnetwork_free(struct vnetwork *vnet)
{
	if (vnet) {
		pki_passport_destroy(vnet->passport);
		linkst_free(vnet->linkst);
		ftable_delete(vnet->ftable);
		ctable_delete(vnet->ctable);
		ctable_delete(vnet->atable);
		bitpool_free(vnet->bitpool);
		session_free(vnet->access_session);
		free(vnet->id);
		free(vnet->uuid);
		free(vnet);
	}
}

void vnetworks_free()
{
/*
	uint32_t i;
	context_t *context = NULL;

	for (i = 0; i < CONTEXT_LIST_SIZE; i++) {
		context = context_table[i];
		context_free(context);
	}
*/
}

struct vnetwork *vnetwork_disable(const char *uuid)
{
	struct vnetwork *vnet = NULL;
	struct vnetwork *vnet_id = NULL;
	if ((vnet = vnetwork_lookup(uuid)) != NULL) {
		RB_REMOVE(vnetwork_tree, &vnetworks, vnet);

		if ((vnet_id = vnetwork_lookup_id(vnet->id)) != NULL) {
			RB_REMOVE(vnetwork_tree_id, &vnetworks_id, vnet_id);
		}
	}

	return vnet;
}

int vnetwork_create(char *id, char *uuid, char *address, char *netmask,
			char *serverCert, char *serverPrivkey, char *trustedCert)
{
	struct vnetwork *vnet;

	vnet = malloc(sizeof(struct vnetwork));
	vnet->uuid = strdup(uuid);
	vnet->id = strdup(id);

	vnet->passport = pki_passport_load_from_memory(serverCert, serverPrivkey, trustedCert);

	bitpool_new(&vnet->bitpool, MAX_NODE);
	vnet->linkst = linkst_new(MAX_NODE, TIMEOUT_SEC);
	vnet->active_node = 0;

	vnet->session_list = NULL;
	vnet->access_session = session_new();

	vnet->ftable = ftable_new(MAX_NODE, session_itemdup, session_itemrel);
	vnet->ctable = ctable_new(MAX_NODE, session_itemdup, session_itemrel);
	vnet->atable = ctable_new(MAX_NODE, session_itemdup, session_itemrel);

	RB_INSERT(vnetwork_tree, &vnetworks, vnet);
	RB_INSERT(vnetwork_tree_id, &vnetworks_id, vnet);

	return 0;
}

int vnetwork_init()
{
	RB_INIT(&vnetworks);
	return 0;
}

RB_GENERATE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);

RB_GENERATE_STATIC(vnetwork_tree_id, vnetwork, entry_id, vnetwork_cmp_id);
