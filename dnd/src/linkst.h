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
#include <sys/queue.h>

struct nodes {

	int index;
	LIST_ENTRY(nodes) nodes;
};
LIST_HEAD(nodelist, nodes);

int linkst_joined(int idx_a, int idx_b, uint8_t **adjacency_matrix, int max_node);
int linkst_join(int idx_a, int idx_b, uint8_t **adjacency_matrix, int max_node);
void linkst_free_nodes(struct nodelist *nodes_head);
struct nodelist *linkst_disjoin(int idx, uint8_t **adjacency_matrix, int active_nodes);
void linkst_free(uint8_t **adjacency_matrix, size_t max_node);
uint8_t **linkst_new(size_t max_node);

#endif
