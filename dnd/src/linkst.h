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

#ifndef LINKST_H
#define LINKST_H

#include <stdint.h>

typedef struct linkst linkst_t;

int linkst_joined(int idx_a, int idx_b, linkst_t **adjacency_matrix, int max_node);
int linkst_join(int idx_a, int idx_b, linkst_t **adjacency_matrix, int max_node);
void linkst_disjoin(int idx, linkst_t **adjacency_matrix, int active_nodes);
void linkst_free(linkst_t **adjacency_matrix, uint32_t max_node);
linkst_t **linkst_new(uint32_t max_node);

#endif
