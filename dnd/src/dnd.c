/* dnd.c: Dynamic Network Daemon
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#include <dnds/event.h>
#include <dnds/journal.h>
#include <dnds/netbus.h>
#include <dnds/net.h>
#include <dnds/inet.h>
#include <dnds/dnds.h>

#include "context.h"
#include "dnd.h"
#include "dsc.h"
#include "session.h"

static void forward_ethernet(session_t *session, DNDSMessage_t *msg)
{
	int ret;
	uint8_t *frame;
	size_t frame_size;

	uint8_t macaddr_src[ETHER_ADDR_LEN];
	uint8_t macaddr_dst[ETHER_ADDR_LEN];
	uint8_t macaddr_dst_type;

	session_t *session_dst = NULL;
	session_t *session_src = NULL;
	session_t *session_list = NULL;

	if (session->auth != SESS_AUTHENTICATED)
		return;

	DNDSMessage_get_ethernet(msg, &frame, &frame_size);

	/* New mac address ? Add it to the lookup table */
	inet_get_mac_addr_src(frame, macaddr_src);
	session_src = ftable_find(session->context->ftable, macaddr_src);
	if (session_src == NULL) {
		memcpy(session->mac_addr, macaddr_src, ETHER_ADDR_LEN);
		ftable_insert(session->context->ftable, macaddr_src, session);
		context_add_session(session->context, session);
		session_src = session;

		JOURNAL_DEBUG("dnd]> new ID [%d]\n", session->id);
	}

	/* Lookup the destination */
	inet_get_mac_addr_dst(frame, macaddr_dst);
	macaddr_dst_type = inet_get_mac_addr_type(macaddr_dst);
	session_dst = ftable_find(session->context->ftable, macaddr_dst);

	if (macaddr_dst_type == ADDR_MULTICAST) {
		/* Multicast is not supported yet */
		return;
	}

	/* Switch forwarding */
	if (macaddr_dst_type == ADDR_UNICAST		/* The destination address is unicast */
		&& session_dst != NULL
		&& session_dst->netc != NULL) {		/* AND the session is up */

			//JOURNAL_DEBUG("dnd]> forwarding the packet to [%s]", session_dst->ip);
			ret = net_send_msg(session_dst->netc, msg);

			int lstate = 0;
			lstate = linkst_joined(session_src->id, session_dst->id, session_src->context->linkst, 1024);
			if (!lstate) {
				p2pRequest(session_src, session_dst);
				linkst_join(session_src->id, session_dst->id, session_src->context->linkst, 1024);
			}

	/* Switch flooding */
	} else if (macaddr_dst_type == ADDR_BROADCAST ||	/* This packet has to be broadcasted */
		session_dst == NULL)  {				/* OR the fib session is down */

			session_list = session->context->session_list;
			while (session_list != NULL) {
				ret = net_send_msg(session_list->netc, msg);
				session_list = session_list->next;
			}
	} else {
		JOURNAL_WARN("dnd]> unknown packet");
	}
}

static int validate_msg(DNDSMessage_t *msg)
{
	pdu_PR pdu;
	DNDSMessage_get_pdu(msg, &pdu);

	if (pdu != pdu_PR_dnm) {
		//JOURNAL_DEBUG("dnd]> not a valid DNM pdu");
		return -1;
	}

	return 0;
}

static void dispatch_operation(session_t *session, DNDSMessage_t *msg)
{
	dnop_PR operation;

	DNMessage_get_operation(msg, &operation);

	switch (operation) {

		case dnop_PR_authRequest:
			authRequest(session, msg);
			break;

		case dnop_PR_netinfoRequest:
			handle_netinfo_request(session, msg);
			break;

		case dnop_PR_p2pRequest:
			p2pRequest(session, msg);
			break;

                /* TerminateRequest is a special case since
                 * it has no Response message associated with it,
		 * simply disconnect the client
		 */
		case dnop_PR_NOTHING:
		default:
		case dnop_PR_terminateRequest:
			session_terminate(session);
			break;
	}
}

void handle_netinfo_request(session_t *session, DNDSMessage_t *msg)
{
	NetinfoRequest_get_ipLocal(msg, session->ip_local);
	NetinfoRequest_get_macAddr(msg, session->tun_mac_addr);

	printf("client local ip %s\n", session->ip_local);
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			session->tun_mac_addr[0],
			session->tun_mac_addr[1],
			session->tun_mac_addr[2],
			session->tun_mac_addr[3],
			session->tun_mac_addr[4],
			session->tun_mac_addr[5]);

	transmit_netinfo_response(session->netc);
}

void transmit_netinfo_response(netc_t *netc)
{
	char *ip_address;
	session_t *session = netc->ext_ptr;

	context_t *context = NULL;
	context = session->context;

	/* Send to the client his network informations */
	ip_address = ippool_get_ip(context->ippool);
	session->ip = strdup(ip_address);
	JOURNAL_DEBUG("session ip %s", session->ip);

	DNDSMessage_t *msg = NULL;
	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoResponse);

	NetinfoResponse_set_ipAddress(msg, ip_address);
	NetinfoResponse_set_netmask(msg, "255.255.255.0");	/* TODO find the real netmask */

	JOURNAL_DEBUG("dnd]> client ip address %s", ip_address);

	net_send_msg(session->netc, msg);

	transmit_peerconnectinfo(ConnectState_connected,
				session->ip, "demo");

}

static void on_secure(netc_t *netc)
{
	size_t nbyte;
	session_t *session;
	session = netc->ext_ptr;

	if (session->auth == SESS_WAIT_STEP_UP) {

		/* Set the session as authenticated */
		session->auth = SESS_AUTHENTICATED;

		/* Send a message to acknowledge the client */
		DNDSMessage_t *msg = NULL;
		DNDSMessage_new(&msg);
		DNDSMessage_set_channel(msg, 0);
		DNDSMessage_set_pdu(msg, pdu_PR_dnm);

		DNMessage_set_seqNumber(msg, 1);
		DNMessage_set_ackNumber(msg, 0);
		DNMessage_set_operation(msg, dnop_PR_authResponse);

		AuthResponse_set_result(msg, DNDSResult_success);
		nbyte = net_send_msg(session->netc, msg);

		DNDSMessage_del(msg);
		msg = NULL;
	}
}

static void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	session_t *session;
	mbuf_t **mbuf_itr;
	pdu_PR pdu;

	mbuf_itr = &netc->queue_msg;
	session = (session_t *)netc->ext_ptr;

	while (*mbuf_itr != NULL) {

		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;
		DNDSMessage_get_pdu(msg, &pdu);

		switch (pdu) {
			case pdu_PR_dnm:	/* DNDS protocol */
				dispatch_operation(session, msg);
				break;
			case pdu_PR_ethernet:	/* Ethernet */
				forward_ethernet(session, msg);
				break;
			default:
				/* TODO disconnect session */
				JOURNAL_ERR("dnd]> invalid PDU");
				break;
		}

		mbuf_del(mbuf_itr, *mbuf_itr);
	}
}

static void on_connect(netc_t *netc)
{
	session_t *session = NULL;

	session = session_new();
	if (session == NULL) {
		JOURNAL_ERR("dnd]> unable to create a new session");
		net_disconnect(netc);
		return;
	}

	session->netc = netc;
	netc->ext_ptr = session;

	return;
}

static void on_disconnect(netc_t *netc)
{
	int ret = 0;
	session_t *session = NULL;

	JOURNAL_DEBUG("dnd]> disconnect");

	session = netc->ext_ptr;

	if (session->auth == SESS_NOT_AUTHENTICATED) {
		session_free(session);
		return;
	}

	/* Remove the session from the context session list */
	context_del_session(session->context, session);
	ftable_erase(session->context->ftable, session->mac_addr);

	if (session->ip != NULL) {
		JOURNAL_DEBUG("dnd]> disconnecting ip {%s}", session->ip);
		ippool_release_ip(session->context->ippool, session->ip);
	}

	transmit_peerconnectinfo(ConnectState_disconnected,
				session->ip, "demo");

	session_free(session);

	return;
}

void dnd_fini(void *ext_ptr)
{

}

int dnd_init(char *listen_addr, char *port)
{
	int ret;

	event_register(EVENT_EXIT, "dnd]> dnd_fini", dnd_fini, PRIO_AGNOSTIC);

	ret = net_server(listen_addr, port, NET_PROTO_UDT, NET_SECURE_ADH, NULL,
		on_connect, on_disconnect, on_input, on_secure);

	if (ret < 0) {
		JOURNAL_ERR("dnd]> net_server failed :: %s:%i", __FILE__, __LINE__);
		return -1;
	}

	context_init();
	return 0;
}

void p2pRequest(session_t *session_a, session_t *session_b)
{
	DNDSMessage_t *msg;

	uint32_t port;
	char *ip_a;
	char *ip_b;

	if (!strcmp(session_a->netc->peer->host, session_b->netc->peer->host)) {

		ip_a = strdup(session_a->ip_local);
		ip_b = strdup(session_b->ip_local);
	} else {

		ip_a = strdup(session_a->netc->peer->host);
		ip_b = strdup(session_b->netc->peer->host);
	}

	/* basic random port : 49152–65535 */
	port = rand() % (65535-49152+1)+49152;

	printf("A ip public %s\n", ip_a);
	printf("B ip public %s\n", ip_b);

	/* msg session A */
	DNDSMessage_new(&msg);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_operation(msg, dnop_PR_p2pRequest);

	P2pRequest_set_macAddrDst(msg, session_b->tun_mac_addr);
	P2pRequest_set_ipAddrDst(msg, ip_b);
	P2pRequest_set_port(msg, port);
	P2pRequest_set_side(msg, P2pSide_client);

	net_send_msg(session_a->netc, msg);

	/* msg session B */
	DNDSMessage_new(&msg);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_operation(msg, dnop_PR_p2pRequest);

	P2pRequest_set_macAddrDst(msg, session_a->tun_mac_addr);
	P2pRequest_set_ipAddrDst(msg, ip_a);
	P2pRequest_set_port(msg, port);
	P2pRequest_set_side(msg, P2pSide_client);

	net_send_msg(session_b->netc, msg);
}
