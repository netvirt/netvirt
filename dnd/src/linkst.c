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

#include <stdio.h>
#include <stdlib.h>

#include "linkst.h"

int linkst_joined(int idx_a, int idx_b, uint8_t **adjacency_matrix, int max_node)
{
	if (idx_a < 0 || idx_a > max_node || idx_b < 0 || idx_b > max_node)
		return -1;

	if (adjacency_matrix == NULL)
		return -1;

	if (adjacency_matrix[idx_a][idx_b] == 1
		&& adjacency_matrix[idx_b][idx_a] == 1) {

		return 1; /* nodes are joined */
	}

	return 0;
}

int linkst_join(int idx_a, int idx_b, uint8_t **adjacency_matrix, int max_node)
{
	if (idx_a < 0 || idx_a > max_node || idx_b < 0 || idx_b > max_node)
		return -1;

	if (adjacency_matrix == NULL)
		return -1;

	adjacency_matrix[idx_a][idx_b] = 1;
	adjacency_matrix[idx_b][idx_a] = 1;

	return 0;
}

void linkst_disjoin(int idx, uint8_t **adjacency_matrix, int active_node)
{
	int i;

	if (idx < 0 || idx > active_node)
		return;

	if (adjacency_matrix == NULL)
		return;

	for (i = 0; i <= active_node; i++) {	/* 0 to active_node-1 gives `active_node` iterations */

		if (adjacency_matrix[idx][i] == 1) {
			adjacency_matrix[idx][i] = 0;
			adjacency_matrix[i][idx] = 0;
		}
	}

	return;
}

void linkst_free(uint8_t **adjacency_matrix, uint32_t max_node)
{
	uint32_t i;
	for (i = 0; i < max_node; i++)
		free(adjacency_matrix[i]);

	free(adjacency_matrix);
}

/* TODO use a binary based matrix
 * use half of a matrix
 */
uint8_t **linkst_new(uint32_t max_node)
{
	uint32_t i;
	uint8_t **adjacency_matrix;
	adjacency_matrix = calloc(max_node, sizeof(uint8_t *));
	for (i = 0; i < max_node; i++)
		adjacency_matrix[i] = calloc(max_node, sizeof(uint8_t));

	return adjacency_matrix;
}

#if 0
int main()
{
	int max_node = 10;
	uint8_t **linkst;

//	uint8_t *bitpool;
//	bitpool_new(&bitpool, max_node);

	/* there is 4 active nodee */
	int idx_a, idx_b, idx_c, idx_d;
	int active_nodes = 0;

	idx_a = 1; //bitpool_allocate_bit(bitpool, max_node, &idx_a);
	active_nodes++;

	idx_b = 2; //bitpool_allocate_bit(bitpool, max_node, &idx_b);
	active_nodes++;

	idx_c = 3; //bitpool_allocate_bit(bitpool, max_node, &idx_c);
	active_nodes++;

	idx_d = 4; //bitpool_allocate_bit(bitpool, max_node, &idx_d);
	active_nodes++;

	linkst = linkst_new(max_node);

	linkst_join(idx_a, idx_b, linkst, max_node);
	linkst_join(idx_a, idx_d, linkst, max_node);

	int state;

	state = linkst_joined(idx_a, idx_b, linkst, max_node);
	printf("state [%d] || [%d] %s [%d]\n", state, idx_a, state == 1 ? "<==>": "//", idx_b);

	state = linkst_joined(idx_a, idx_c, linkst, max_node);
	printf("state [%d] || [%d] %s [%d]\n", state, idx_a, state == 1 ? "<==>": "//", idx_c);


	struct nodelist *nodes_head = linkst_disjoin(idx_a, linkst, active_nodes);
//	bitpool_release_bit(bitpool, max_node, idx_a);
	struct nodes *np;

	for (np = nodes_head->lh_first; np != NULL; np = np->nodes.le_next) {
           printf("[%d] ====> [%d]\n", idx_a, np->index);
	}

	linkst_free_nodes(nodes_head);
	linkst_free(linkst, max_node);
//	bitpool_free(bitpool);
}
#endif
