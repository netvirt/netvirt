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

#ifndef BITV_H
#define BITV_H

#include <stdint.h>

int bitpool_release_bit(uint8_t bitpool[], size_t nbits, uint32_t bit);
int bitpool_allocate_bit(uint8_t bitpool[], size_t nbits, uint32_t *bit);
void bitpool_free(uint8_t *bitpool);
int bitpool_new(uint8_t **bitpool, size_t nbits);

#endif
