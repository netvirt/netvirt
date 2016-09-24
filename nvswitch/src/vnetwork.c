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

#include "hash.h"
#include "inet.h"
#include "tree.h"
#include "vnetwork.h"

RB_HEAD(vnetwork_tree, vnetwork);
static struct vnetwork_tree	vnetworks;

static int vnetwork_cmp(const struct vnetwork *, const struct vnetwork *);
RB_PROTOTYPE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);

static int vnetwork_cmp(const struct vnetwork *a, const struct vnetwork *b)
{
	return strcmp(a->uuid, b->uuid);
}

void vnetwork_del_session(struct vnetwork *vnet, struct session *s)
{
	LIST_REMOVE(s, entry);
	vnet->active_node--;
}

struct session *
vnetwork_new_session(struct vnetwork *vnet)
{
	struct session *s;

	s = malloc(sizeof(*s));
	LIST_INSERT_HEAD(&vnet->sessions, s, entry);

	return s;
}

void vnetwork_show_session_list(struct vnetwork *vnet)
{
}

struct vnetwork *vnetwork_lookup(const char *uuid)
{
	struct vnetwork match;

	match.uuid = (char *)uuid;
	return RB_FIND(vnetwork_tree, &vnetworks, &match);
}

void vnetwork_free(struct vnetwork *vnet)
{
	if (vnet) {
		pki_passport_destroy(vnet->passport);
		linkst_free(vnet->linkst);
		ftable_delete(vnet->ftable);
		ctable_delete(vnet->ctable);
		ctable_delete(vnet->atable);
		free(vnet->uuid);
		free(vnet);
	}
}

void vnetworks_free()
{
}

struct vnetwork *vnetwork_disable(const char *uuid)
{
	struct vnetwork *vnet = NULL;
	if ((vnet = vnetwork_lookup(uuid)) != NULL)
		RB_REMOVE(vnetwork_tree, &vnetworks, vnet);

	return vnet;
}

#if 0
void *
session_itemdup(const void *item)
{
	return (void*)item;
}

void
session_itemrel(void *item)
{
	(void)item;
}
#endif

int
vnetwork_create(char *id, char *uuid, char *address, char *netmask,
			char *cert, char *privkey, char *cacert)
{
	struct vnetwork *vnet;

	vnet = malloc(sizeof(struct vnetwork));

	vnet->uuid = strdup(uuid);
	vnet->passport = pki_passport_load_from_memory(cert, privkey, cacert);
	vnet->linkst = linkst_new(MAX_NODE, TIMEOUT_SEC);
	vnet->active_node = 0;
	LIST_INIT(&vnet->sessions);

	vnet->ftable = ftable_new(MAX_NODE, NULL, NULL);
	vnet->ctable = ctable_new(MAX_NODE, NULL, NULL);
	vnet->atable = ctable_new(MAX_NODE, NULL, NULL);

	RB_INSERT(vnetwork_tree, &vnetworks, vnet);

	return 0;
}

int vnetwork_init()
{
	RB_INIT(&vnetworks);
	return 0;
}

RB_GENERATE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);
