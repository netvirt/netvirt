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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "linkst.h"

typedef struct linkst {
	uint8_t linked;
	time_t timestamp;
} linkst_t;

int linkst_joined(int idx_a, int idx_b, linkst_t **adjacency_matrix, int max_node)
{
	time_t now;

	if (idx_a < 0 || idx_a > max_node || idx_b < 0 || idx_b > max_node)
		return -1;

	if (adjacency_matrix == NULL)
		return -1;

	time(&now);

	if (adjacency_matrix[idx_a][idx_b].linked == 1
		&& adjacency_matrix[idx_b][idx_a].linked == 1
		/* check for timeout 5min */
		&& difftime(now, adjacency_matrix[idx_a][idx_b].timestamp) < 300
		&& difftime(now, adjacency_matrix[idx_b][idx_a].timestamp) < 300) {

		return 1; /* nodes are joined */
	}

	return 0;
}

int linkst_join(int idx_a, int idx_b, linkst_t **adjacency_matrix, int max_node)
{
	if (idx_a < 0 || idx_a > max_node || idx_b < 0 || idx_b > max_node)
		return -1;

	if (adjacency_matrix == NULL)
		return -1;

	adjacency_matrix[idx_a][idx_b].linked = 1;
	adjacency_matrix[idx_b][idx_a].linked = 1;

	time(&adjacency_matrix[idx_a][idx_b].timestamp);
	time(&adjacency_matrix[idx_b][idx_a].timestamp);

	return 0;
}

void linkst_disjoin(int idx, linkst_t **adjacency_matrix, int active_node)
{
	int i;

	if (idx < 0 || idx > active_node)
		return;

	if (adjacency_matrix == NULL)
		return;

	for (i = 0; i <= active_node; i++) {	/* 0 to active_node-1 gives `active_node` iterations */

		if (adjacency_matrix[idx][i].linked == 1) {
			adjacency_matrix[idx][i].linked = 0;
			adjacency_matrix[i][idx].linked = 0;

			adjacency_matrix[idx][i].timestamp = 0;
			adjacency_matrix[i][idx].timestamp = 0;
		}
	}

	return;
}

void linkst_free(linkst_t **adjacency_matrix, uint32_t max_node)
{
	uint32_t i;
	for (i = 0; i < max_node; i++)
		free(adjacency_matrix[i]);

	free(adjacency_matrix);
}

/* TODO use half of a matrix */
linkst_t **linkst_new(uint32_t max_node)
{
	uint32_t i;
	linkst_t **adjacency_matrix;
	adjacency_matrix = calloc(max_node, sizeof(linkst_t *));
	for (i = 0; i < max_node; i++)
		adjacency_matrix[i] = calloc(max_node, sizeof(linkst_t));

	return adjacency_matrix;
}

#if 0
int main()
{
	int max_node = 10;
	linkst_t **linkst;

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
	int i = 305;

	while (i--) {

		state = linkst_joined(idx_a, idx_b, linkst, max_node);
		printf("state [%d] || [%d] %s [%d]\n", state, idx_a, state == 1 ? "<==>": "//", idx_b);

		state = linkst_joined(idx_a, idx_c, linkst, max_node);
		printf("state [%d] || [%d] %s [%d]\n", state, idx_a, state == 1 ? "<==>": "//", idx_c);

		printf("\n\n");

		sleep(1);
	}

	linkst_disjoin(idx_a, linkst, active_nodes);

	linkst_free(linkst, max_node);
}
#endif
