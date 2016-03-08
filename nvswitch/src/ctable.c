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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsw_hlib.h"
#include "ctable.h"
#include "hash.h"

#define UUID_STR_LEN 36

// hash function
static unsigned ctable_hash(const void *uuid)
{
	unsigned h = hashword((uint32_t*)uuid, 8, 0);

	return h;
}

// key comparison function
static int ctable_cmp(const void *uuid_a, const void *uuid_b)
{
	return memcmp(uuid_a, uuid_b, UUID_STR_LEN);
}

// key copying function
static void *ctable_keydup(const void *uuid)
{
	char *uuid_dup;

	uuid_dup = calloc(1, UUID_STR_LEN+1);
	memcpy(uuid_dup, uuid, UUID_STR_LEN+1);

	return uuid_dup;
}

// key deletion function
static void ctable_keyrel(void *key)
{
	free(key);
}

ctable_t *ctable_new(size_t size, itemdup_f session_itemdup, itemrel_f session_itemrel)
{
	return jsw_hnew(size, ctable_hash, ctable_cmp,
			ctable_keydup, session_itemdup,
			ctable_keyrel, session_itemrel);
}

void ctable_delete(ctable_t *ctable)
{
	jsw_hdelete(ctable);
}

void *ctable_find(ctable_t *ctable, char *uuid)
{
	return jsw_hfind(ctable, uuid);
}

int ctable_insert(ctable_t *ctable, char *uuid, void *session)
{
	return jsw_hinsert(ctable, uuid, session);
}

int ctable_erase(ctable_t *ctable, char *uuid)
{
	return jsw_herase(ctable, uuid);
}
