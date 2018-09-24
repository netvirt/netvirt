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

#ifndef _WIN32

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#if defined(OPENBSD)
# include <net/if_dl.h>
#endif
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#if defined(OPENBSD)
#include <ifaddrs.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "inet.h"

const uint8_t	 macaddr_broadcast[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
const uint8_t	 macaddr_multicast[ETHER_ADDR_LEN] = { 0x01, 0x00, 0x5e, 0x0, 0x0, 0x0 };

uint16_t
inet_ethertype(void *frame)
{
	struct ether_header	*hd = frame;

	return (ntohs(hd->ether_type));
}

int
inet_macaddr_type(uint8_t *macaddr)
{
	if (memcmp(macaddr, macaddr_broadcast, ETHER_ADDR_LEN) == 0)
		return (ADDR_BROADCAST);
	else if (memcmp(macaddr, macaddr_multicast, 1) == 0)
		return (ADDR_MULTICAST);

	/* "these addresses are physical station addresses, not multicast nor
	 * broadcast, so the second hex digit (reading from the left) will be
	 * even, not odd."
	 * http://www.iana.org/assignments/ethernet-numbers
	 */

	 /* FIXME we must implement a solid mechanism based on the odd/even principle,
	 * furthermore, would be nice to lookup the ethernet card vendor name.
	 */
	return (ADDR_UNICAST);
}

void
inet_macaddr_dst(void *frame, uint8_t *macaddr)
{
	struct ether_header	*eth_hdr = frame;
	memcpy(macaddr, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
}

void
inet_macaddr_src(void *frame, uint8_t *macaddr)
{
	struct ether_header	*eth_hdr = frame;
	memcpy(macaddr, eth_hdr->ether_shost, ETHER_ADDR_LEN);
}

void
inet_print_addr(void *frame)
{
	struct ether_header	*eth_hdr = frame;

	printf("maddr_dst: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0],
		eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
		eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

	printf("macaddr_src: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0],
		eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
		eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

	printf("type: %x\n", htons(eth_hdr->ether_type));
}

void
inet_print_macaddr(uint8_t *macaddr)
{
	printf("maddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	macaddr[0],
	macaddr[1],
	macaddr[2],
	macaddr[3],
	macaddr[4],
	macaddr[5]);
}

#endif
