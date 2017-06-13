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

#include <sys/tree.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>

#include <log.h>
#include <bitv.h>

#include "inet.h"
#include "switch.h"

RB_HEAD(vnetwork_tree, vnetwork);

static int	vnetwork_cmp(const struct vnetwork *, const struct vnetwork *);
RB_PROTOTYPE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);

static struct vnetwork_tree	vnetworks;

int
vnetwork_cmp(const struct vnetwork *a, const struct vnetwork *b)
{
	return strcmp(a->uid, b->uid);
}

struct vnetwork
*vnetwork_lookup(const char *uid)
{
	struct vnetwork	match;

	match.uid = (char *)uid;
	return RB_FIND(vnetwork_tree, &vnetworks, &match);
}

void
vnetwork_free(struct vnetwork *vnet)
{
	if (vnet == NULL)
		return;

	pki_passport_destroy(vnet->passport);
	SSL_CTX_free(vnet->ctx);
	free(vnet->uid);
	free(vnet);
}

int
vnetwork_create(char *uid, char *cert, char *pvkey, char *cacert)
{
	struct vnetwork *vnet;

	if ((vnet = malloc(sizeof(*vnet))) == NULL) {
		log_warnx("%s: malloc", __func__);
		return (-1);
	}

	vnet->uid = strdup(uid);
	vnet->passport = pki_passport_load_from_memory(cert, pvkey, cacert);
	vnet->active_node = 0;
	vnet->ctx = NULL;

	RB_INSERT(vnetwork_tree, &vnetworks, vnet);

	return (0);
}

int
vnetwork_init(void)
{
	RB_INIT(&vnetworks);
	return (0);
}

RB_GENERATE_STATIC(vnetwork_tree, vnetwork, entry, vnetwork_cmp);
