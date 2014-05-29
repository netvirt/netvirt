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

#ifndef DNDS_MBUF_H
#define DNDS_MBUF_H

#include <stdint.h>
#include <sys/types.h>

#define MBUF_BYVAL	0x1		// copy the data
#define MBUF_BYREF	0x2		// reference the data, usefull with data not serialized

typedef struct mbuf {

	struct mbuf *next;		// next mbuf
	struct mbuf *prev;		// prev mbuf

	size_t count;			// the number of element

	uint8_t mem_type;		// memory type [MBUF_BYVAL, MBUF_BYREF]

	uint8_t *ext_buf;		// start of buffer
	uint32_t ext_size;		// size of buffer

	void (*free_cb)(void *ext_buf);	// external free, use with MBUF_BYREF

} mbuf_t;

void mbuf_free(mbuf_t **mbuf);
int mbuf_count(mbuf_t *mbuf_head);
int mbuf_add(mbuf_t **, mbuf_t *);
int mbuf_del(mbuf_t **, mbuf_t *);
mbuf_t *mbuf_new(const void *buf, size_t data_size, uint8_t mem_type, void (*free)(void *));

#endif
