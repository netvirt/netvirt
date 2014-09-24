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

#include <stdlib.h>

#include "bitv.h"

static int get_bit(const uint8_t bitmap[], size_t bit)
{
        return (bitmap[bit/8] >> (bit % 8)) & 1;
}

static void set_bit(uint8_t bitmap[], size_t bit)
{
        bitmap[bit/8] |= (1 << (bit % 8));
}

static void clear_bit(uint8_t bitmap[], size_t bit)
{
        bitmap[bit/8] &= ~(1 << (bit % 8));
}

int bitpool_release_bit(uint8_t bitpool[], size_t nbits, uint32_t bit)
{
        if (bit < nbits) {
                clear_bit(bitpool, bit);
                return 0;
        }

        return -1;
}

int bitpool_allocate_bit(uint8_t bitpool[], size_t nbits, uint32_t *bit)
{
        uint32_t i, j, nbyte;

        nbyte = nbits/8;

        for (i = 0; (i < nbyte) && (bitpool[i] == 0xff); i++);

        if (i == nbyte)
                return -1;      /* bitpool is full ! */

        for (j = 0; get_bit(bitpool + i, j); j++);

        *bit = i * 8 + j;

        set_bit(bitpool, *bit);

        return 0;
}
void bitpool_free(uint8_t *bitpool)
{
        free(bitpool);
}

int bitpool_new(uint8_t **bitpool, size_t nbits)
{
        int nbyte = (nbits+7)/8;
        *bitpool = calloc(nbyte, sizeof(uint8_t));

        return *bitpool != NULL;
}

