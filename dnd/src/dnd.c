/* * dnd.c: Dynamic Network Daemon
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
#include "session.h"

static void forward_ethernet(session_t *session, DNDSMessage_t *msg)
{
	int ret;
	uint8_t *frame;
	size_t frame_size;

	uint8_t mac_addr_src[6];
	uint8_t mac_addr_dst[6];
	uint8_t mac_addr_dst_type;

	session_t *session_dst = NULL;
	session_t *session_src = NULL;
	session_t *session_list = NULL;


	if (session->auth != SESS_AUTHENTICATED)
		return;

	DNDSMessage_get_ethernet(msg, &frame, &frame_size);

	// New mac address ? add it to the lookup table
	inet_get_mac_addr_src(frame, mac_addr_src);
	session_src = ftable_find(session->context->ftable, mac_addr_src);
	if (session_src == NULL) {
		memcpy(session->mac_addr, mac_addr_src, 6);
		ftable_insert(session->context->ftable, mac_addr_src, session);
		context_add_session(session->context, session);
	}

	// Lookup the destination
	inet_get_mac_addr_dst(frame, mac_addr_dst);
	mac_addr_dst_type = inet_get_mac_addr_type(mac_addr_dst);
	session_dst = ftable_find(session->context->ftable, mac_addr_dst);

	if (mac_addr_dst_type == ADDR_MULTICAST) {
		//JOURNAL_DEBUG("dnd]> doesn't support multicast yet :: %s:%i", __FILE__, __LINE__);
		return;
	}

	// Switch forwarding
	if (mac_addr_dst_type == ADDR_UNICAST		// the destination address is unicast
		&& session_dst != NULL
		&& session_dst->netc != NULL) {		// AND the session is up

			//JOURNAL_DEBUG("dnd]> forwarding the packet to [%s]", session_dst->ip);
			ret = net_send_msg(session_dst->netc, msg);

			//JOURNAL_DEBUG("dnd]> forwarded {%i} bytes to %s", ret, session_dst->ip);
	}
	// Switch flooding
	else if (mac_addr_dst_type == ADDR_BROADCAST ||	// this packet has to be broadcasted
		session_dst == NULL)  {			// OR the fib session is down

			//JOURNAL_DEBUG("dnd]> BROADCASTING");
			session_list = session->context->session_list;
			if (session_list == NULL) {
				//JOURNAL_DEBUG("dnd]> the session list is empty :: %s:%i", __FILE__, __LINE__);
			}

			while (session_list != NULL) {
				ret = net_send_msg(session_list->netc, msg);
				//JOURNAL_DEBUG("dnd]> BR forwarded {%i} bytes to %s ", ret, session_list->ip);

				session_list = session_list->next;
			}

	}
	else {
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

		case dnop_PR_p2pRequest:
			p2pRequest(session, msg);
			break;

                // terminateRequest is a special case since
                // it has no Response message associated with it,
		// simply disconnect the client
		case dnop_PR_NOTHING:
		default:
		case dnop_PR_terminateRequest:
			session_terminate(session);
			break;
	}
}

static void on_secure(netc_t *netc)
{
	size_t nbyte;
	char *ip_address;
	session_t *session;
	context_t *context = NULL;

	session = netc->ext_ptr;
	context = session->context;

	if (session->auth == SESS_WAIT_STEP_UP) {

		// Set the session as authenticated
		session->auth = SESS_AUTHENTICATED;

		// Send a message to inform the client
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

		// Send to the client its network information
		ip_address = ippool_get_ip(context->ippool);
		session->ip = strdup(ip_address);
		JOURNAL_DEBUG("session ip %s", session->ip);

		DNDSMessage_new(&msg);
		DNDSMessage_set_channel(msg, 0);
		DNDSMessage_set_pdu(msg, pdu_PR_dnm);

		DNMessage_set_seqNumber(msg, 1);
		DNMessage_set_ackNumber(msg, 0);
		DNMessage_set_operation(msg, dnop_PR_netinfoResponse);

		NetinfoResponse_set_ipAddress(msg, ip_address);
		// TODO - find the real netmask
		NetinfoResponse_set_netmask(msg, "255.255.255.0");

		JOURNAL_DEBUG("dnd]> client ip address %s", ip_address);

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
		DNDSMessage_printf(msg);

		DNDSMessage_get_pdu(msg, &pdu);

		switch (pdu) {
			case pdu_PR_dnm:	// DNDS protocol
				dispatch_operation(session, msg);
				break;
			case pdu_PR_ethernet:	// ethernet
				forward_ethernet(session, msg);
				break;
			default:		// invalid PDU
				// TODO - error
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

	// remove the session from the context session list
	context_del_session(session->context, session);
	ftable_erase(session->context->ftable, session->mac_addr);

	if (session->ip != NULL) {
		JOURNAL_DEBUG("dnd]> disconnecting ip {%s}", session->ip);
		ippool_release_ip(session->context->ippool, session->ip);
	}

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


#define RDV_PORT_MIN 1025
#define RDV_PORT_MAX 65535


void p2pRequest(port_t *port, struct rdv *rdv_request)
{

	struct rdv *rdv_request_meetat1 = NULL;
	struct rdv *rdv_request_meetat2 = NULL;
	RDV_ASK *rdv_request_ask = NULL;
	RDV_ASK *rdv_ask_table_entry = NULL;
	fib_entry_t *fib_dest = NULL; // destinator
	port_t *port_dest = NULL;
	uint32_t rdv_request_length = 0;
	uint32_t hash;
	uint16_t portnumber; // (int)12345, rendez-vous port
	char portnumberstr[6]; // used to (int)12345 => "12345"

	if (rdv_request == NULL) {
		JOURNAL_ERR("dnd]> rdv request was null");
		return;
	}

	rdv_ntoh(rdv_request);

	rdv_print(rdv_request);

	dnd (rdv_request->type) {
		case RDV_REQUEST_ASK:
			JOURNAL_DEBUG("dnd]> %s asked a rendez-vous", port->ip);
			rdv_request_ask = (RDV_ASK *)((uint8_t *)rdv_request + sizeof(struct rdv));

			// 1. Find who wants to talk to who
			fib_dest = fib_lookup(port->context->fib_cache, rdv_request_ask->dest_mac);
			if (fib_dest == NULL) {
				JOURNAL_ERR("dnd]> unknown mac addr for rendezvous");
				return;
			}
			port_dest = fib_dest->port;

			// 2. Check if there is a rendez-vous request pending for the node
			hash = rdvask_hash(rdv_request_ask->dest_mac, rdv_request_ask->src_mac);
			rdv_ask_table_entry = table_rdvask[hash];

			if (rdv_ask_table_entry != NULL) {
				// Generate a random port
				srand((unsigned int)time(NULL));
				portnumber = rand()%((RDV_PORT_MAX-RDV_PORT_MIN)+1)+RDV_PORT_MIN;
				snprintf(portnumberstr, 6, "%d", portnumber);

				// 3. If so, check if they are using the same public IP
				if (strcmp(port_dest->xtpc->peer->host, port->xtpc->peer->host) == 0) {
					// 4. Yes, use the provided private ip
					rdv_request_meetat1 = rdv_meetat(rdv_request_ask->dest_mac, rdv_ask_table_entry->local_ip, portnumberstr, RDV_STATE_LISTEN);
					rdv_request_meetat2 = rdv_meetat(rdv_request_ask->src_mac, rdv_request_ask->local_ip, portnumberstr, RDV_STATE_CONNECT);
				}
				else {
					// 4. No, use their public ip
					rdv_request_meetat1 = rdv_meetat(rdv_request_ask->dest_mac, port_dest->xtpc->peer->host, portnumberstr, RDV_STATE_LISTEN);
					rdv_request_meetat2 = rdv_meetat(rdv_request_ask->src_mac, port->xtpc->peer->host, portnumberstr, RDV_STATE_CONNECT);
				}

				rdv_request_length = rdv_request_meetat1->length;

				rdv_hton(rdv_request_meetat1);
				xtp_send(port->xtpc, 0, rdv_request_meetat1, rdv_request_length, XTP_TYPE_RDV);

				rdv_hton(rdv_request_meetat2);
				xtp_send(port_dest->xtpc, 0, rdv_request_meetat2, rdv_request_length, XTP_TYPE_RDV);

				// 5. Delete the rendezvous request from the table
				free(rdv_ask_table_entry);
				table_rdvask[hash] = NULL;
			}
			else {
				// 3. Add the rendezvous request ask to the table
				hash = rdvask_hash(rdv_request_ask->src_mac, rdv_request_ask->dest_mac);

				rdv_ask_table_entry = malloc(sizeof(RDV_ASK));
				strncpy(rdv_ask_table_entry->local_ip, rdv_request_ask->local_ip, 15);
				strncpy(rdv_ask_table_entry->src_mac, rdv_request_ask->src_mac, 6);
				strncpy(rdv_ask_table_entry->dest_mac, rdv_request_ask->dest_mac, 6);

				table_rdvask[hash] = rdv_ask_table_entry;
			}

			break;
		case RDV_REQUEST_MEETAT:
			// TODO - wat a rendezvous meetat to the dnd o_q ?
			JOURNAL_WARN("dnd]> received a RDV_REQUEST_MEETAT");
			break;
		default:
			// TODO - error
			JOURNAL_WARN("dnd]> received unknown RDV type (%d)", rdv_request->type);
			return;
	}
}



