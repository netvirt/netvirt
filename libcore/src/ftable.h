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

#ifndef FTABLE_H
#define FTABLE_H

#include <stdint.h>
#include <stdlib.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

typedef struct jsw_hash ftable_t;

ftable_t *ftable_new(size_t size, void *(*itemdup_f)(const void *item), void (*itemrel_f)(void *item));
void ftable_delete(ftable_t *ftable);
void *ftable_find(ftable_t *ftable, uint8_t *mac);
int ftable_insert(ftable_t *ftable, uint8_t *mac, void *item);
int ftable_erase(ftable_t *ftable, uint8_t *mac);

#endif
