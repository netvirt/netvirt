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
#include "dnc.h"
#include "p2p.h"

ftable_t *ftable = NULL;

static void p2p_on_secure(netc_t *netc)
{
	printf("p2p_on_secure\n");
}

static void p2p_on_connect(netc_t *netc)
{
	printf("p2p_on_secure\n");
}

static void p2p_on_disconnect(netc_t *netc)
{
	printf("p2p_on_disconnect\n");
}

void p2p_on_input(netc_t *netc)
{
	on_input(netc);
}

struct session *p2p_find_session(uint8_t *eth_frame)
{
	uint8_t mac_dst[ETHER_ADDR_LEN];
	memcpy(mac_dst, eth_frame, ETHER_ADDR_LEN);
/*
	printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_dst[0], mac_dst[1],
							mac_dst[2], mac_dst[3],
*/							mac_dst[4], mac_dst[5]);
	return ftable_find(ftable, mac_dst);
}

void *op_p2p_request(void *ptr)
{
	char dest_addr[INET_ADDRSTRLEN];
	uint8_t mac_dst[ETHER_ADDR_LEN];
	uint32_t port;
	char port_str[6];
	struct session *p2p_session;
	int state = 1;
	netc_t *netc = NULL;

	struct p2p_arg *args = ptr;

	P2pRequest_get_macAddrDst(args->msg, mac_dst);
	P2pRequest_get_ipAddrDst(args->msg, dest_addr);
	P2pRequest_get_port(args->msg, &port);

	snprintf(port_str, 6, "%d", port);
	netc = net_p2p("0.0.0.0", dest_addr, port_str, NET_PROTO_UDT, NET_UNSECURE, state,
				p2p_on_connect, p2p_on_secure, p2p_on_disconnect, p2p_on_input);

	if (netc == NULL) {
		jlog(L_NOTICE, "dnc]> p2p failed");
		return NULL;
	}

	p2p_session = calloc(1, sizeof(struct session));
	p2p_session->netc = netc;

	jlog(L_NOTICE, "dnc]> p2p connected");
	ftable_insert(ftable, mac_dst, p2p_session);

	p2p_session->tapcfg = args->session->tapcfg;

	printf("p2p_session: %p netc: %p\n", p2p_session, p2p_session->netc);
	p2p_session->tapcfg = args->session->tapcfg;
	p2p_session->state = SESSION_STATE_AUTHED;
	p2p_session->netc->ext_ptr = p2p_session;

	return NULL;
}

void p2p_init()
{
	ftable = ftable_new(1024, session_itemdup, session_itemrel);
}
