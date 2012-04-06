/*
 * mbuf.c: Memory buffer API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "journal.h"
#include "mbuf.h"

/* TODO
 * add() and del() have to be rewritten, its a kludge
 * use single pointer for the mbuf_head
 * base everything on the mbuf->count
 * write an initialization function ex: mbuf_init_list(netc->queue_out);
*/

int mbuf_count(mbuf_t *mbuf_head)
{
	if (mbuf_head == NULL)
		return 0;

	return mbuf_head->count;
}

int mbuf_add(mbuf_t **mbuf_head, mbuf_t *mbuf)
{
	if (*mbuf_head == NULL) {
		*mbuf_head = mbuf;
		(*mbuf_head)->next = NULL;
		(*mbuf_head)->prev = mbuf;
		(*mbuf_head)->count = 1;
	}
	else {
		mbuf->next = NULL;
		mbuf->prev = (*mbuf_head)->prev;
		(*mbuf_head)->prev->next = mbuf;
		(*mbuf_head)->prev = mbuf;
		(*mbuf_head)->count++;
	}

	return 0;
}

int mbuf_del(mbuf_t **mbuf_head, mbuf_t *mbuf)
{
	if (*mbuf_head == NULL || mbuf == NULL)
		return -1;

	if (mbuf == (*mbuf_head)->prev) {
		(*mbuf_head)->prev = mbuf->prev;
	}

	if (mbuf != *mbuf_head) {
		mbuf->prev->next = mbuf->next;
	}

	if (mbuf->next != NULL) {
		mbuf->next->prev = mbuf->prev;
	}

	if (mbuf == *mbuf_head && mbuf != NULL) {
		*mbuf_head = mbuf->next;
	}

	if (mbuf == *mbuf_head && mbuf->next == NULL) {
		*mbuf_head = NULL;
	}

	// XXX a bit crappy
	if (*mbuf_head != NULL) {
		(*mbuf_head)->count--;
	}

	// Release the memory
	if (mbuf->mem_type == MBUF_BYVAL) {
		free(mbuf->ext_buf);
	}
	else if (mbuf->mem_type == MBUF_BYREF) {
		mbuf->free(mbuf->ext_buf);
	}

	free(mbuf);

	return 0;
}

void mbuf_free(mbuf_t **mbuf)
{
	while (*mbuf != NULL)
		mbuf_del(mbuf, *mbuf);
}

mbuf_t *mbuf_new(const void *buf, size_t data_size, uint8_t mem_type, void (*free)(void *))
{
	mbuf_t *mbuf = NULL;

	switch (mem_type) {

		case MBUF_BYVAL:
			mbuf = (mbuf_t *)calloc(1, sizeof(mbuf_t));
			mbuf->mem_type = mem_type;
			mbuf->ext_buf = (uint8_t *)malloc(data_size);
			mbuf->ext_size = data_size;
			memmove(mbuf->ext_buf, buf, data_size);
			break;

		case MBUF_BYREF:
			mbuf = (mbuf_t *)calloc(1, sizeof(mbuf_t));
			mbuf->mem_type = mem_type;
			mbuf->ext_buf = (uint8_t *)buf;
			mbuf->free = free;
			break;
	}

	return mbuf;
}

void mbuf_print(mbuf_t **mbuf_head)
{
	mbuf_t *mbuf;

	for (mbuf = *mbuf_head; mbuf != NULL; mbuf = mbuf->next) {
			printf("mbuf{%i}||", mbuf->ext_size);

	}
}
