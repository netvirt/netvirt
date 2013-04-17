/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifndef DNDS_BITPOOL_H
#define DNDS_BITPOOL_H

#include <stdint.h>

int bitpool_release_bit(uint8_t bitpool[], size_t nbits, uint32_t bit);
int bitpool_allocate_bit(uint8_t bitpool[], size_t nbits, uint32_t *bit);
void bitpool_free(uint8_t *bitpool);
int bitpool_new(uint8_t **bitpool, size_t nbits);

#endif
