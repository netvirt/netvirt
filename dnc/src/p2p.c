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
	struct session *p2p_session;

	if (netc == NULL) {
		jlog(L_ERROR, "dnc]> p2p failed to encrypt to connection...");
		return;
	}

	jlog(L_NOTICE, "dnc]> p2p connection encrypted");

	p2p_session = netc->ext_ptr;
	p2p_session->state = SESSION_STATE_AUTHED;
	p2p_session->netc->ext_ptr = p2p_session;

	ftable_insert(ftable, p2p_session->mac_dst, p2p_session);
}

static void p2p_on_connect(netc_t *netc)
{
	struct session *p2p_session;

	if (netc == NULL) {
		jlog(L_NOTICE, "dnc]> p2p connection failed");
		return;
	}

	jlog(L_NOTICE, "dnc]> p2p connection established");

	p2p_session = netc->ext_ptr;
	p2p_session->netc = netc;

	return;
}

static void p2p_on_disconnect(netc_t *netc)
{
	struct session *p2p_session = NULL;

	jlog(L_NOTICE, "dnc]> p2p disconnected\n");

	p2p_session = netc->ext_ptr;
	ftable_erase(ftable, p2p_session->mac_dst);
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
							mac_dst[4], mac_dst[5]);
*/
	return ftable_find(ftable, mac_dst);
}

void op_p2p_request(struct session *session, DNDSMessage_t *msg)
{
	char port_str[6];
	uint32_t side = 0;
	uint8_t mac_dst[ETHER_ADDR_LEN];
	char ip_dst[INET_ADDRSTRLEN];
	uint32_t port;
	struct session *p2p_session;

	P2pRequest_get_macAddrDst(msg, mac_dst);
	P2pRequest_get_ipAddrDst(msg, ip_dst);
	P2pRequest_get_port(msg, &port);
	P2pRequest_get_side(msg, &side);

	jlog(L_NOTICE, "dnc]> establishing p2p with %s", ip_dst);

	p2p_session = calloc(1, sizeof(struct session));
	p2p_session->tapcfg = session->tapcfg;
	p2p_session->passport = session->passport;
	memmove(p2p_session->mac_dst, mac_dst, ETHER_ADDR_LEN);

	snprintf(port_str, 6, "%d", port);
	net_p2p("0.0.0.0", ip_dst, port_str, NET_PROTO_UDT, NET_SECURE_RSA, side, p2p_session->passport,
		p2p_on_connect, p2p_on_secure, p2p_on_disconnect, p2p_on_input, (void *)p2p_session);

	return;
}

void p2p_init()
{
	ftable = ftable_new(1024, session_itemdup, session_itemrel);
}
