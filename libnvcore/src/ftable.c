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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsw_hlib.h"
#include "ftable.h"
#include "hash.h"

// hash function
static unsigned ftable_hash(const void *mac)
{
	uint8_t key[ETHER_ADDR_LEN+2] = {0};
	memcpy(key, mac, ETHER_ADDR_LEN);
	memcpy(key+ETHER_ADDR_LEN, mac, 2);

	unsigned h = hashword((uint32_t*)key, 2, 0);

	return h;
}

// key comparison function
static int ftable_cmp(const void *a, const void *b)
{
	return memcmp(a, b, ETHER_ADDR_LEN);
}

// key copying function
static void *ftable_keydup(const void *key)
{
	uint8_t *mac_dup;

	mac_dup = calloc(1, ETHER_ADDR_LEN);
	memcpy(mac_dup, key, ETHER_ADDR_LEN);

	return mac_dup;
}

// key deletion function
static void ftable_keyrel(void *key)
{
	free(key);
}

ftable_t *ftable_new(size_t size, itemdup_f itemdup, itemrel_f itemrel)
{
	return jsw_hnew(size, ftable_hash, ftable_cmp,
			ftable_keydup, itemdup,
			ftable_keyrel, itemrel);
}

void ftable_delete(ftable_t *ftable)
{
	jsw_hdelete(ftable);
}

void *ftable_find(ftable_t *ftable, uint8_t *mac)
{
	return jsw_hfind(ftable, mac);
}

int ftable_insert(ftable_t *ftable, uint8_t *mac, void *item)
{
	return jsw_hinsert(ftable, mac, item);
}

int ftable_erase(ftable_t *ftable, uint8_t *mac)
{
	return jsw_herase(ftable, mac);
}
