/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
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
