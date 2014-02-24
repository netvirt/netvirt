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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ippool.h"

static int get_bit(const uint8_t bitmap[], size_t bit)
{
	return (bitmap[bit/8] >> (bit % 8)) & 1;
}

static void set_bit(uint8_t bitmap[], size_t bit)
{
	bitmap[bit/8] |= (1 << (bit % 8));
}

static void reset_bit(uint8_t bitmap[], size_t bit)
{
	bitmap[bit/8] &= ~(1 << (bit % 8));
}

static int alloc_bitmap(size_t bits, uint8_t **bitmap)
{
	int byte_size = (bits+7)/8;
	*bitmap = calloc(byte_size, sizeof(uint8_t));
	return *bitmap != 0;
}

static int allocate_bit(uint8_t bitmap[], size_t bits, uint32_t *bit)
{
	int i, j, byte_size;

	byte_size = bits/8;

	/* byte */
	for (i = 0; (i < byte_size) && (bitmap[i] == 0xff); i++);
	if (i == byte_size)
		return 0;

	/* bit */
	for (j = 0; get_bit( bitmap+i, j); j++);

	*bit = i * 8 + j;
	set_bit(bitmap, *bit);

	return 1;
}

static int free_bit(uint8_t bitmap[], size_t bits, size_t bit)
{
	if (bit < bits) {
		reset_bit(bitmap, bit);
		return 1;
	}
	return 0;
}

char *ippool_get_ip(ippool_t *ippool)
{
	struct in_addr new_addr;
	uint32_t bit = 0;
	int ret = 0;

	ret = allocate_bit(ippool->pool, ippool->hosts, &bit);
	if (ret == 0) /* IP pool is depleeted */
		return NULL;

	new_addr = ippool->hostmin;
	new_addr.s_addr = htonl((ntohl(new_addr.s_addr) + bit));

	return inet_ntoa(new_addr);
}

void ippool_release_ip(ippool_t *ippool, char *ip)
{
	int bit = 0;
	struct in_addr addr;
	inet_aton(ip, &addr);

	bit = ntohl(addr.s_addr) - ntohl(ippool->hostmin.s_addr);
	free_bit(ippool->pool, ippool->hosts, bit);
}

void ipcalc(ippool_t *ippool, char *address, char *netmask)
{
	struct in_addr mask;

	inet_pton(AF_INET, "255.255.255.255", &mask);

	inet_pton(AF_INET, address, &ippool->address);
	inet_pton(AF_INET, netmask, &ippool->netmask);

	ippool->hosts = ntohl(mask.s_addr - ippool->netmask.s_addr);
	ippool->hostmax.s_addr = (ippool->address.s_addr | ~ippool->netmask.s_addr) - htonl(1);
	ippool->hostmin.s_addr = ippool->hostmax.s_addr - htonl(ippool->hosts-2);
}

ippool_t *ippool_new(char *address, char *netmask)
{
	ippool_t *ippool;

	ippool = malloc(sizeof(ippool_t));

	ipcalc(ippool, address, netmask);
	alloc_bitmap(ippool->hosts, &(ippool->pool));

	return ippool;
}
/*
int main()
{
	char *ip = NULL;
	ippool_t *my_pool = NULL;

	my_pool = ippool_new("44.128.1.0", "255.255.255.0");

	do {
		ip = ippool_get_ip(my_pool);
		if (ip)
			printf("ip: %s\n", ip);
	} while (ip);

	printf("the end!\n");
}
*/
