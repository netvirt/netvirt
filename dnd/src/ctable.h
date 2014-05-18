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

#ifndef CTABLE_H
#define CTABLE_H

#include <stdint.h>
#include <stdlib.h>

typedef struct jsw_hash ctable_t;

ctable_t *ctable_new(size_t size, void *(*itemdup_f)(const void *session), void (*itemrel_f)(void *session));
void ctable_delete(ctable_t *ctable);
void *ctable_find(ctable_t *ctable, char *uuid);
int ctable_insert(ctable_t *ctable, char *uuid, void *session);
int ctable_erase(ctable_t *ctable, char *uuid);

#endif
