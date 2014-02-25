/*
 * inet.c: TCP/IP related functions API
 *
 * Copyright (C) 2009 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

#include "inet.h"
#include "logger.h"
#include "udt.h"

/* TODO
 * fixing nomenclature
 * cleaning functions structure etc...
 * using DNDS frame instead of peer buffer
 */

#if defined(OPENBSD)
# define CMD_GET_LOCAL_IP "ifconfig `route -n show | grep default | awk '{print $8}'` | grep -w 'inet' | awk '{print $2}'"
#else
# define CMD_GET_LOCAL_IP "/sbin/ifconfig `ip route show | grep default | awk '{print $5}'` | grep 'inet addr' | cut -d: -f2 | awk '{print $1}'"
#endif

const uint8_t mac_addr_broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
const uint8_t mac_addr_multicast[6] = { 0x01, 0x00, 0x5e, 0x0, 0x0, 0x0 };
const uint8_t mac_addr_empty[6] = { 0, 0, 0, 0, 0, 0 };


// Link layer
int inet_get_mac_addr_type(uint8_t *mac_addr)
{
	if (memcmp(mac_addr, mac_addr_broadcast, ETHER_ADDR_LEN) == 0) {
		return ADDR_BROADCAST;
	}
	else if (memcmp(mac_addr, mac_addr_multicast, 1) == 0) {
		return ADDR_MULTICAST;
	}

	/* "these addresses are physical station addresses, not multicast nor
	 * broadcast, so the second hex digit (reading from the left) will be
	 * even, not odd."
	 * http://www.iana.org/assignments/ethernet-numbers
	 * FIXME we must implement a solid mechanism based on the odd/even principle,
	 * furthermore, would be nice to lookup the ethernet card vendor name.
	 */
	return ADDR_UNICAST;
}

int inet_get_mac_addr_dst(void *data, uint8_t *mac_addr)
{
	struct ether_header *eth_hdr;
	eth_hdr = data;

	bcopy(eth_hdr->ether_dhost, mac_addr, ETHER_ADDR_LEN);

	return 0;
}

int inet_get_mac_addr_src(void *data, uint8_t *mac_addr)
{
	struct ether_header *eth_hdr;
	eth_hdr = data;

	bcopy(eth_hdr->ether_shost, mac_addr, ETHER_ADDR_LEN);

	return 0;
}

// Internet layer
uint16_t inet_get_iphdr_len(void *data)
{
	struct ip *iph;
	iph = data + sizeof(struct ether_header);
	return ntohl(iph->ip_len);
}

void inet_print_iphdr(void *data)
{
	struct ip *iph;
	iph = data + sizeof(struct ether_header);
	jlog(L_DEBUG, "inet]> iphdr len: %i", iph->ip_len);
}

int inet_is_ipv4(void *data)
{
	struct ether_header *hd;
	hd = data;

	if (htons(hd->ether_type) == 0x800)
		return 1;

	return 0;
}

size_t inet_get_ipv4(void *data, char *ip)
{
	struct ip *ip_header;
	char *inet_ip;

	if (inet_is_ipv4(data)) {
		ip_header = (data + sizeof(struct ether_header));
		inet_ip = inet_ntoa(ip_header->ip_dst);
		memcpy(ip, inet_ip, strlen(inet_ip));
		return strlen(inet_ip);
	}

	return -1;
}

int inet_is_ipv6(void *data)
{
	struct ether_header *hd;
	hd = data;

	if (htons(hd->ether_type) == 0x86DD) {
		return 1;
	}

	return 0;
}

/*
 * Get the local IP that correspond to the default gateway interface IP.
 */
int inet_get_local_ip(char *ip, size_t ip_len)
{
	FILE *process = NULL;
	char local_ip[17]; // max_size (15 + \n + \0)

	process = popen(CMD_GET_LOCAL_IP, "r");

	if (process == NULL) {
		// Unable to open the process
		return -1;
	}

	if (fgets(local_ip, 17, process) == NULL) {
		// Unable to read / no data was available
		pclose(process);
		return -2;
	}

	strncpy(ip, local_ip, 15);
	ip[strlen(local_ip) - 1] = '\0'; // remove the \n

	if (pclose(process) == -1) {
		// Unable to close
		return -3;
	}

	return strlen(ip);
}

/*
 * Get the mac address corresponding to the given interface
 */
int inet_get_iface_mac_address(char *iface_name, uint8_t *mac_address)
{
#if defined(LINUX)
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	mac_address[0] = ifr.ifr_hwaddr.sa_data[0];
	mac_address[1] = ifr.ifr_hwaddr.sa_data[1];
	mac_address[2] = ifr.ifr_hwaddr.sa_data[2];
	mac_address[3] = ifr.ifr_hwaddr.sa_data[3];
	mac_address[4] = ifr.ifr_hwaddr.sa_data[4];
	mac_address[5] = ifr.ifr_hwaddr.sa_data[5];

	return 0;
#endif
#if defined(OPENBSD)
        struct sockaddr_dl *lladdr;
        struct ifaddrs *ifap, *if_itr;

        getifaddrs(&ifap);

        for (if_itr = ifap; if_itr != NULL; if_itr = if_itr->ifa_next) {
                if (!strcmp(iface_name, if_itr->ifa_name)) {
                        if (if_itr->ifa_addr->sa_family == AF_LINK) {
                                lladdr = (struct sockaddr_dl *)if_itr->ifa_addr;

                                mac_address[0] = lladdr->sdl_data[0 + lladdr->sdl_nlen];
                                mac_address[1] = lladdr->sdl_data[1 + lladdr->sdl_nlen];
                                mac_address[2] = lladdr->sdl_data[2 + lladdr->sdl_nlen];
                                mac_address[3] = lladdr->sdl_data[3 + lladdr->sdl_nlen];
                                mac_address[4] = lladdr->sdl_data[4 + lladdr->sdl_nlen];
                                mac_address[5] = lladdr->sdl_data[5 + lladdr->sdl_nlen];

                                freeifaddrs(ifap);
                                return 0;
                        }
                }
        }

        freeifaddrs(ifap);
        return -1
#endif

	return 0;

}

void inet_print_ether_type(void *data)
{
	struct ether_header *hd;
	hd = data;

	jlog(L_DEBUG, "inet]> ether type: %x", htons(hd->ether_type));
}

void inet_print_ethernet(void *data)
{
	struct ether_header *hd;
	hd = data;

	jlog(L_DEBUG, "inet]> ether_dhost: %02x:%02x:%02x:%02x:%02x:%02x", hd->ether_dhost[0],
		hd->ether_dhost[1], hd->ether_dhost[2], hd->ether_dhost[3],
		hd->ether_dhost[4], hd->ether_dhost[5]);

	jlog(L_DEBUG, "inet]> ether_shost: %02x:%02x:%02x:%02x:%02x:%02x", hd->ether_shost[0],
		hd->ether_shost[1], hd->ether_shost[2], hd->ether_shost[3],
		hd->ether_shost[4], hd->ether_shost[5]);

	jlog(L_DEBUG, "inet]> ether_type: %x", htons(hd->ether_type));
}

void inet_print_arp(peer_t *peer)
{
	struct ether_header *hd;
	struct ether_arp *ea;

	hd = peer->buffer;

	if (htons(hd->ether_type) == 0x806) { // ARP Request
		ea = peer->buffer + sizeof(struct ether_header);

		jlog(L_DEBUG, "inet]> arp_hdr: %i", ea->arp_hrd);

		jlog(L_DEBUG, "inet]> arp_sha:  %02x:%02x:%02x:%02x:%02x:%02x", ea->arp_sha[0],
			ea->arp_sha[1], ea->arp_sha[2], ea->arp_sha[3],
			ea->arp_sha[4], ea->arp_sha[5]);
		jlog(L_DEBUG, "inet]> arp_spa: %02x:%02x:%02x:%02x", ea->arp_spa[0],
			ea->arp_spa[1], ea->arp_spa[2], ea->arp_spa[3]);

		jlog(L_DEBUG, "inet]> arp_tha: %02x:%02x:%02x:%02x:%02x:%02x", ea->arp_tha[0],
			ea->arp_tha[1], ea->arp_tha[2], ea->arp_sha[3],
			ea->arp_tha[4], ea->arp_sha[5]);
		jlog(L_DEBUG, "inet]> arp_tpa: %02x:%02x:%02x:%02x", ea->arp_tpa[0],
			ea->arp_tpa[1], ea->arp_tpa[2], ea->arp_tpa[3]);
	}
}
