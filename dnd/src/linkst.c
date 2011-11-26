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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/queue.h>

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
struct nodes {

	int index;
	LIST_ENTRY(nodes) nodes;
};
LIST_HEAD(nodelist, nodes);

void linkst_free_nodes(struct nodelist *nodes_head)
{
	struct nodes *node;

	while (nodes_head->lh_first != NULL) {
		node = nodes_head->lh_first;
		LIST_REMOVE(nodes_head->lh_first, nodes);
		free(node);
	}
}

struct nodelist *linkst_disjoin(int idx, uint8_t **adjacency_matrix, int active_nodes)
{
	if (idx < 0 || idx > active_nodes)
		return NULL;

	if (adjacency_matrix == NULL)
		return NULL;

	struct nodelist *nodes_head = malloc(sizeof(struct nodelist));
	struct nodes *node;
	int i;

	for (i=0; i<=active_nodes; i++) {	/* 0 to active_nodes-1 gives `active_nodes` iterations */

		if (adjacency_matrix[idx][i] == 1) {
			adjacency_matrix[idx][i] = 0;
			adjacency_matrix[i][idx] = 0;

			node = malloc(sizeof(struct nodes));
			node->index = i;
			LIST_INSERT_HEAD(nodes_head, node, nodes);
		}
	}

	return nodes_head;
}

void linkst_free(uint8_t **adjacency_matrix, size_t max_node)
{
	int i;
	for (i=0; i<max_node; i++)
		free(adjacency_matrix[i]);

	free(adjacency_matrix);
}

uint8_t **linkst_new(size_t max_node)
{
	int i;
	uint8_t **adjacency_matrix;
	adjacency_matrix = calloc(max_node, sizeof(uint8_t *));
	for (i=0; i<max_node; i++)
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
