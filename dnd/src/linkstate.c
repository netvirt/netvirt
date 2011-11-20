/*
 * linkstate.c: Active link-state topology control
 *
 * Copyright (C) 2011 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

/* Under development
 * TODO
 * use an index pool
 * ...
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int linkst_join(int idx_a, int idx_b, uint8_t **adj_matrix, int max_node)
{
	if (idx_a < 0 || idx_a > max_node || idx_b < 0 || idx_b > max_node)
		return -1;

	if (adj_matrix == NULL)
		return -1;

	adj_matrix[idx_a][idx_b] = 1;
	adj_matrix[idx_b][idx_a] = 1;

	return 0;
}

struct nodes *linkst_disjoin(int idx, uint8_t **adj_matrix, int active_nodes)
{
	if (idx < 0 || idx > active_nodes)
		return NULL;

	if (adj_matrix == NULL)
		return NULL;;

	int i;

	for (i=0; i<=active_nodes; i++) {	/* 0 to active_nodes-1 gives `active_nodes` iterations */

		if (adj_matrix[idx][i] == 1) {
			adj_matrix[idx][i] = 0;
			adj_matrix[i][idx] = 0;
			printf("[%d] ---> [%d]\n", idx, i);
		}
	}

	/* XXX Build the list of nodes that was joint with the node that is leaving */	
	return NULL;
}

uint8_t **linkst_new_matrix(int max_node)
{
	int i;
	uint8_t **matrix;
	matrix = calloc(max_node, sizeof(uint8_t *));
	for (i = 0; i < max_node; i++)
		matrix[i] = calloc(max_node, sizeof(uint8_t));

	return matrix;
}
int main()
{
	int max_node = 10;
	uint8_t **adj_matrix;

	/* there is 4 active nodee */
	int idx_a = 1;
	int idx_b = 2;
	int idx_c = 3;
	int idx_d = 4;
	int active_nodes = 4;	/* will be dynamically adjusted when node arrive/depart from the network */

	adj_matrix = linkst_new_matrix(max_node);

	linkst_join(idx_a, idx_b, adj_matrix, max_node);
	linkst_join(idx_a, idx_d, adj_matrix, max_node);
	linkst_disjoin(idx_a, adj_matrix, active_nodes);
}
