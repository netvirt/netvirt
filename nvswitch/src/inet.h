/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#define ADDR_UNICAST	0x1
#define ADDR_BROADCAST	0x2
#define ADDR_MULTICAST	0x4
#define ETHERTYPE_PING	0x9000

uint16_t	inet_ethertype(void *);
int		inet_macaddr_type(uint8_t *);
void		inet_macaddr_dst(void *, uint8_t *);
void		inet_macaddr_src(void *, uint8_t *);
void		inet_print_addr(void *);

#endif
