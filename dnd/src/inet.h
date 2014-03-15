#ifndef DNDS_INET_H
#define DNDS_INET_H

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

#endif /* DNDS_INET_H */
