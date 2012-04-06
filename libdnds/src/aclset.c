/*
 * aclset.c: Access List API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsw_rbtree.h"
#include "aclset.h"

/* TODO
 * replace all printf() with journal
 */

typedef struct acl {

	uint32_t id;
	ipset_t *ipset;
} acl_t;

static int aclset_cmp(const void *p1, const void *p2)
{
	acl_t *acl1, *acl2;

	acl1 = (acl_t*)p1;
	acl2 = (acl_t*)p2;

	if (acl1->id > acl2->id)
		return 1;

	else if (acl1->id < acl2->id)
		return -1;

	/* (acl1->id == acl2->id) */
	return 0;
}


static void *aclset_dup(void *p)
{
	void *dup_p;

	dup_p = calloc(1, sizeof(acl_t));
	memmove(dup_p, p, sizeof(acl_t));

	return dup_p;
}

static void aclset_rel(void *p)
{
	free(p);
}

aclset_t *aclset_new()
{
	jsw_rbtree_t *rbtree;
	rbtree = jsw_rbnew(aclset_cmp, aclset_dup, aclset_rel);

	return rbtree;
}

void aclset_delete(aclset_t *aclset)
{
	jsw_rbdelete(aclset);
}

int aclset_insert(aclset_t *aclset, uint32_t id, ipset_t *ipset)
{
	int ret;

	acl_t *acl;
	acl = calloc(1, sizeof(acl_t));

	acl->id = id;
	acl->ipset = ipset;

	ret = jsw_rbinsert(aclset, (void *)acl);
	if (ret == 0) {
		printf("aclset]> insert failed on acl id %i\n", id);
		free(acl);
		return -1;
	}

	return 0;
}

int aclset_erase(aclset_t *aclset, uint32_t id)
{
	int ret;
	acl_t *acl;

	acl = calloc(1, sizeof(acl_t));

	ret = jsw_rberase(aclset, (void*)acl);
	if (ret == 0) {
		printf("aclset]> erase failed on acl id %i\n", id);
		free(acl);
		return -1;
	}

	return 0;
}

ipset_t *aclset_find(aclset_t *aclset, uint32_t id)
{
	acl_t *acl, acl_find;

	acl_find.id = id;
	acl = jsw_rbfind(aclset, &acl_find);

	return acl->ipset;
}

void aclset_printset(aclset_t *aclset)
{
	acl_t *acl;

	jsw_rbtrav_t *rbtrav;
	rbtrav = jsw_rbtnew();

	acl = (acl_t*)jsw_rbtfirst(rbtrav, aclset);
	printf("id %i\n", acl->id);

	while ((acl = jsw_rbtnext(rbtrav)) != NULL) {
		printf("id %i\n", acl->id);
	}
}
