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

#include <dnds.h>
#include <ftable.h>
#include <logger.h>
#include <netbus.h>

#include "session.h"

ftable_t *ftable = NULL;

static void p2p_on_connect(netc_t *netc)
{
	printf("p2p_on_connect\n");
}

static void p2p_on_secure(netc_t *netc)
{
	printf("p2p_on_secure\n");
}

static void p2p_on_disconnect(netc_t *netc)
{
	printf("p2p_on_disconnect\n");
}

void p2p_on_input(netc_t *netc)
{

}

struct session *p2p_find_session(uint8_t *eth_frame)
{
	return NULL;
}

void op_p2p_request(struct session *session, DNDSMessage_t *msg)
{
	printf("on_p2p_request\n");
	char dest_addr[INET_ADDRSTRLEN];
	uint8_t mac_dst[ETHER_ADDR_LEN];
	uint32_t port;
	char port_str[6];
	netc_t *p2p_netc;
	int state = 1;

	P2pRequest_get_macAddrDst(msg, mac_dst);
	P2pRequest_get_ipAddrDst(msg, dest_addr);
	P2pRequest_get_port(msg, &port);

	snprintf(port_str, 6, "%d", port);
	p2p_netc = net_p2p("0.0.0.0", dest_addr, port_str, NET_PROTO_UDT, NET_UNSECURE, state,
				p2p_on_connect, p2p_on_secure, p2p_on_disconnect, p2p_on_input);

	if (p2p_netc != NULL) {
		jlog(L_NOTICE, "dnc]> p2p connected!");
		ftable_insert(ftable, mac_dst, p2p_netc->ext_ptr);
	} else {
		jlog(L_NOTICE, "dnc]> p2p unable to connect!");
	}
}

void p2p_init()
{
	ftable = ftable_new(1024, session_itemdup, session_itemrel);
}
