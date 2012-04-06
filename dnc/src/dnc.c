/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
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
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include <dnds/dnds.h>
#include <dnds/journal.h>
#include <dnds/mbuf.h>
#include <dnds/net.h>
#include <dnds/netbus.h>
#include <dnds/pki.h>
#include <dnds/tun.h>
#include <dnds/inet.h>
#include <dnds/ftable.h>

#include "dnc.h"
#include "session.h"

static void dispatch_operation(struct session *session, DNDSMessage_t *msg);

static ftable_t *ftable;
struct session *master_session;

static void tunnel_in(iface_t *iface)
{
	DNDSMessage_t *msg = NULL;
	struct session *session = NULL;
	struct session *p2p_session = NULL;
	size_t frame_size = 0;

	uint8_t macaddr_src[ETHER_ADDR_LEN];
	uint8_t macaddr_dst[ETHER_ADDR_LEN];
	uint8_t macaddr_dst_type;

	session = (struct session*)iface->ext_ptr;
	if (session->status != SESSION_STATUS_AUTHED) {
		return;	/* not authenticated yet ! */
	}

	frame_size = iface->read(iface);

	inet_get_mac_addr_src(iface->frame, macaddr_src);
	inet_get_mac_addr_dst(iface->frame, macaddr_dst);
	macaddr_dst_type = inet_get_mac_addr_type(macaddr_dst);

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_ethernet);
	DNDSMessage_set_ethernet(msg, iface->frame, frame_size);

	/* Any p2p connection already established ? if so, route the packet to the p2p link.
	 * Otherwise the packet is sent to the server, where he will be switched to the right node.
	 */
	p2p_session = ftable_find(ftable, macaddr_dst);
	if (p2p_session && p2p_session->status == SESSION_STATUS_AUTHED) {
		session = p2p_session;
	}

	net_send_msg(session->netc, msg);
}

static void tunnel_out(iface_t *iface, DNDSMessage_t *msg)
{
	uint8_t *frame;
	size_t frame_size;

	DNDSMessage_get_ethernet(msg, &frame, &frame_size);
	iface->write(iface, frame, frame_size);
}

static void terminate(struct session *session)
{
	net_disconnect(session->netc);
	free(session);
}

void transmit_netinfo_request(struct session *session)
{
	inet_get_local_ip(session->ip_local, INET_ADDRSTRLEN);
	inet_get_iface_mac_address(session->iface->devname, session->tun_mac_addr);

	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoRequest);

	NetinfoRequest_set_ipLocal(msg, session->ip_local);
	NetinfoRequest_set_macAddr(msg, session->tun_mac_addr);

	net_send_msg(session->netc, msg);
}

void transmit_register(netc_t *netc)
{
	X509_NAME *subj_ptr;
	char subj[256];
        size_t nbyte;
	struct session *session = (struct session *)netc->ext_ptr;

        DNDSMessage_t *msg;

        DNDSMessage_new(&msg);
        DNDSMessage_set_channel(msg, 0);
        DNDSMessage_set_pdu(msg, pdu_PR_dnm);

        DNMessage_set_seqNumber(msg, 1);
        DNMessage_set_ackNumber(msg, 0);
        DNMessage_set_operation(msg, dnop_PR_authRequest);

	subj_ptr = X509_get_subject_name(session->passport->certificate);
	X509_NAME_get_text_by_NID(subj_ptr, NID_commonName, subj, 256);

	JOURNAL_NOTICE("dnc> my common name: %s\n", subj);
        AuthRequest_set_certName(msg, subj, strlen(subj));

        nbyte = net_send_msg(netc, msg);
        if (nbyte == -1) {
                JOURNAL_NOTICE("dnc]> malformed message\n", nbyte);
                return;
        }

        JOURNAL_NOTICE("dnc]> sent %i bytes\n", nbyte);
	session->status = SESSION_STATUS_WAIT_ANSWER;

        return;
}

static void on_disconnect(netc_t *netc)
{
	printf("on_disconnect !!\n");

	struct session *session;
	session = netc->ext_ptr;
}

/* only used by P2P */
static void on_connect(netc_t *netc)
{
	printf("on_connect\n");

	struct session *session = NULL;
        session = malloc(sizeof(struct session));

        if (netc->conn_type == NET_P2P_CLIENT) {
                session->type = SESSION_TYPE_P2P_CLIENT;
        } else {
                session->type = SESSION_TYPE_P2P_SERVER;
        }

        session->status = SESSION_STATUS_AUTHED;
        session->iface = master_session->iface;
        session->netc = netc;
	netc->ext_ptr = session;
}

static void p2p_on_secure(netc_t *netc)
{
}

static void on_secure(netc_t *netc)
{
	JOURNAL_NOTICE("dnc]> on_secure !");

	struct session *session;
	session = netc->ext_ptr;

	if (session->status == SESSION_STATUS_NOT_AUTHED) {
		transmit_register(netc);
	}
}

static void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	struct session *session;
	mbuf_t **mbuf_itr;
	pdu_PR pdu;

	mbuf_itr = &netc->queue_msg;
	session = netc->ext_ptr;

	while (*mbuf_itr != NULL) {

		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;

		DNDSMessage_get_pdu(msg, &pdu);
		switch (pdu) {
			case pdu_PR_dnm:
				dispatch_operation(session, msg);
				break;

			case pdu_PR_ethernet:
				tunnel_out(session->iface, msg);
				break;

			default: /* Invalid PDU */
				terminate(session);
				return;
		}

		mbuf_del(mbuf_itr, *mbuf_itr);
	}
}

static void dispatch_operation(struct session *session, DNDSMessage_t *msg)
{
	dnop_PR operation;
	e_DNDSResult result;

	char dest_addr[INET_ADDRSTRLEN];
	uint32_t port;
	char port_name[6];
	netc_t *p2p_netc = NULL;
	uint8_t state;
	uint8_t mac_dst[ETHER_ADDR_LEN];
	char ip_addr[INET_ADDRSTRLEN];

	DNMessage_get_operation(msg, &operation);

	switch (operation) {

		case dnop_PR_authResponse:

			AuthResponse_get_result(msg, &result);

			if (result == DNDSResult_success) {
				JOURNAL_INFO("dnc]> session authenticated");
				transmit_netinfo_request(session);
			}
			else if (result == DNDSResult_secureStepUp) {
				JOURNAL_INFO("dnc]> server authentication require step up");
				net_step_up(session->netc);
			}
			else {
				JOURNAL_ERR("dnc]> unknown AuthResponse result (%i)", result);
			}

			break;

		case dnop_PR_netinfoResponse:

			NetinfoResponse_get_ipAddress(msg, ip_addr);
			JOURNAL_INFO("dnc]> got ip address %s\n", ip_addr);

			master_session = session;
			tun_up(session->iface->devname, ip_addr);
			session->status = SESSION_STATUS_AUTHED;

			break;

		case dnop_PR_p2pRequest:

			P2pRequest_get_macAddrDst(msg, mac_dst);
			P2pRequest_get_ipAddrDst(msg, dest_addr);
			P2pRequest_get_port(msg, &port);
		
			snprintf(port_name, 6, "%d", port);
			p2p_netc = net_p2p("0.0.0.0", dest_addr, port_name, NET_PROTO_UDT, NET_UNSECURE, state,
						on_connect, p2p_on_secure, on_disconnect, on_input);

			if (p2p_netc != NULL) {
				JOURNAL_INFO("dnc]> p2p connected");
				ftable_insert(ftable, mac_dst, p2p_netc->ext_ptr);
			} else {
				JOURNAL_INFO("dnc]> p2p unable to connect");
			}

			break;

                /* `terminateRequest` is a special case since it has no
		 * response message associated with it, simply disconnect the client.
		 */
		case dnop_PR_NOTHING:
		default:
			JOURNAL_NOTICE("dnc]> not a valid DNM operation");
		case dnop_PR_terminateRequest:
			terminate(session);
			break;
	}
}

int dnc_init(char *server_address, char *server_port,
		char *certificate, char *privatekey, char *trusted_authority)
{
	netc_t *netc;
	struct session *session;

	session = calloc(1, sizeof(struct session));
	session->passport = pki_passport_load_from_file(certificate,
							 privatekey,
							 trusted_authority);

	netc = net_client(server_address, server_port, NET_PROTO_UDT, NET_SECURE_ADH,
		session->passport, on_disconnect, on_input, on_secure);

	if (netc == NULL) {
		free(session);
		return -1;
	}

	/* Initialize the forward table */
        ftable = ftable_new(1024, session_itemdup, session_itemrel);

	session->iface = NULL;
	session->netc = netc;
	session->status = SESSION_STATUS_NOT_AUTHED;
	netc->ext_ptr = session;

	/* Create the tunnel interface now, so when we register,
	 * we can extract the interface mac address needed by the server.
	 */
	session->iface = netbus_newtun(tunnel_in);
	session->iface->ext_ptr = session;
	tun_up(session->iface->devname, "0.0.0.0");

	return 0;
}
