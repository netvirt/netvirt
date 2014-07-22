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

#ifndef LINKST_H
#define LINKST_H

#include <stdint.h>

typedef struct linkst linkst_t;

int linkst_disjoin(linkst_t *linkst, uint32_t idx);
int linkst_joined(linkst_t *linkst, uint32_t idx_a, uint32_t idx_b);
int linkst_join(linkst_t *linkst, uint32_t idx_a, uint32_t idx_b);

void linkst_free(linkst_t *linkstate);
linkst_t *linkst_new(uint32_t upper_limit, uint16_t timeout_sec);

#endif
