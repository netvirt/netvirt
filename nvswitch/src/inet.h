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

#ifndef INET_H
#define INET_H

#include "udt.h"

#define ADDR_UNICAST	0x1
#define ADDR_BROADCAST	0x2
#define ADDR_MULTICAST	0x4

const uint8_t mac_addr_broadcast[6];
const uint8_t mac_ddr_empty[6];

int inet_get_mac_addr_type(uint8_t *);
int inet_get_mac_addr_dst(void *, uint8_t *);
int inet_get_mac_addr_src(void *, uint8_t *);

uint16_t inet_get_iphdr_len(void *);
void inet_print_iphdr(void *);
int inet_is_ipv4(void *);
size_t inet_get_ipv4(void *, char *);
int inet_is_ipv6(void *);

void inet_print_ether_type(void *);
void inet_print_ethernet(void *);
void inet_print_arp(peer_t *);

#endif
