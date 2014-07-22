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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "linkst.h"

typedef struct linkinfo {
	uint8_t linked;
	time_t timestamp;
} linkinfo_t;

typedef struct linkst {
	linkinfo_t **adjacency_matrix;
	uint32_t matrix_size;
	uint32_t upper_limit;
	uint16_t timeout_sec;
} linkst_t;

static void
linkst_resize(linkst_t *linkst, uint32_t resize_size)
{
	uint32_t i;

	if (linkst == NULL) {
		return;
	}

	if (linkst->matrix_size + resize_size + 5 < linkst->upper_limit) {
		resize_size += 5;
	} else {
		resize_size = linkst->upper_limit - linkst->matrix_size;
	}

	linkst->adjacency_matrix = realloc(linkst->adjacency_matrix,
					(linkst->matrix_size + resize_size) * sizeof(linkinfo_t *));

	for (i = linkst->matrix_size; i < linkst->matrix_size + resize_size; i++) {
		linkst->adjacency_matrix[i] = calloc(i+1, sizeof(linkinfo_t));
	}

	linkst->matrix_size += resize_size;
}

int
linkst_disjoin(linkst_t *linkst, uint32_t idx)
{
	uint32_t i, x, y;

	if (linkst == NULL) {
		return -1;
	}

	if (idx < 1 || idx > linkst->matrix_size) {
		return -1;
	}

	for (i = 1; i <= linkst->matrix_size; i++) {

		if (idx > i) {
			x = idx; y = i;
		} else {
			x = i; y = idx;
		}

		if ((linkst->adjacency_matrix[x-1][y-1]).linked == 1) {
			(linkst->adjacency_matrix[x-1][y-1]).linked = 0;
			(linkst->adjacency_matrix[x-1][y-1]).timestamp = 0;
		}
	}

	return 0;
}

int
linkst_joined(linkst_t *linkst, uint32_t idx_a, uint32_t idx_b)
{
	uint32_t x, y;
	time_t now;

	if (linkst == NULL) {
		return -1;
	}

	if (idx_a < 1 || idx_a > linkst->matrix_size
		|| idx_b < 1 || idx_b > linkst->matrix_size) {
		return -1;
	}

	if (idx_a > idx_b) {
		x = idx_a; y = idx_b;
	} else {
		x = idx_b; y = idx_a;
	}

	time(&now);

	if ((linkst->adjacency_matrix[x-1][y-1]).linked == 1
		&& difftime(now, (linkst->adjacency_matrix[x-1][y-1]).timestamp) < linkst->timeout_sec) {
		return 1; /* nodes are joined */
	}

	return 0;
}

int
linkst_join(linkst_t *linkst, uint32_t idx_a, uint32_t idx_b)
{
	uint32_t x, y;

	if (linkst == NULL) {
		return -1;
	}

	if (idx_a < 1 || idx_a > linkst->upper_limit
		|| idx_b < 1 || idx_b > linkst->upper_limit) {
		return -1;
	}

	if (idx_a > idx_b) {
		x = idx_a; y = idx_b;
	} else {
		x = idx_b; y = idx_a;
	}

	if (x >= linkst->matrix_size) {
		linkst_resize(linkst, x - linkst->matrix_size);
	}

	(linkst->adjacency_matrix[x-1][y-1]).linked = 1;
	time(&(linkst->adjacency_matrix[x-1][y-1]).timestamp);

	return 0;
}

void
linkst_free(linkst_t *linkst)
{
	uint32_t i;

	if (linkst == NULL) {
		return;
	}

	for (i = 1; i <= linkst->matrix_size; i++) {
		free(linkst->adjacency_matrix[i-1]);
	}

	free(linkst->adjacency_matrix);
	free(linkst);
}

linkst_t *
linkst_new(uint32_t upper_limit, uint16_t timeout_sec)
{
	linkst_t *linkst = NULL;

	linkst = calloc(1, sizeof(linkst_t));
	linkst->upper_limit = upper_limit;
	linkst->timeout_sec = timeout_sec;
	linkst->matrix_size = 0;

	return linkst;
}
