/*
 * dnc.c: Dynamic network client
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
#include "request.h"

/* TODO
 * dirty prototype that must be cleaned up
 */

// XXX - temporary for now, there is some kind of dependcy between two static functions
static void dispatch_operation(dn_sess_t *sess, DNDSMessage_t *msg);

static int cert_num = 0;
static ftable_t *ftable;

dn_sess_t *master_sess;
// iface -> vpn
static void tunnel_in(iface_t *iface)
{
	dn_sess_t *session = NULL;
	dn_sess_t *p2p_session = NULL;
	DNDSMessage_t *msg = NULL;
	size_t frame_len = 0;

	uint8_t mac_addr_src[6]; // mac address source (aka our mac addr)
	uint8_t mac_addr_dst[6]; // mac address destinatio
	uint8_t mac_addr_dst_type;

	session = (dn_sess_t *)iface->ext_ptr;
	if (session->auth != SESS_AUTH) {
		//JOURNAL_ERR("dnc]> session not authenticated");
		return;
	}

	frame_len = iface->read(iface);

	inet_get_mac_addr_src(iface->frame, mac_addr_src);
	inet_get_mac_addr_dst(iface->frame, mac_addr_dst);
	mac_addr_dst_type = inet_get_mac_addr_type(mac_addr_dst);
//	printf("mac addr type %d\n", mac_addr_dst_type);

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_ethernet);
	DNDSMessage_set_ethernet(msg, iface->frame, frame_len);
/*
	printf("lookup mac %x\n", mac_addr_dst);
	printf("P2pRequest> mac_addr_dst: %x:%x:%x:%x:%x:%x\n", mac_addr_dst[0],mac_addr_dst[1],mac_addr_dst[2],
                                                    mac_addr_dst[3],mac_addr_dst[4],mac_addr_dst[5]);	


	// Check if we have a P2P connection in the forward table with the dest mac addr
	p2p_session = ftable_find(ftable, mac_addr_dst);

	if (p2p_session == NULL) {
		// Ask for a P2P session
		request_p2p(session->netc, mac_addr_src, mac_addr_dst);
	}
	else if (p2p_session->auth == SESS_AUTH) {
		// Send the message using the P2P session
		session = p2p_session;
	}
*/
	net_send_msg(session->netc, msg);
}

static void terminate(dn_sess_t *sess)
{
	net_disconnect(sess->netc);
	free(sess);
}

static void tunnel_out(iface_t *iface, DNDSMessage_t *msg)
{
	uint8_t *frame;
	size_t length;

	DNDSMessage_get_ethernet(msg, &frame, &length);

	iface->write(iface, frame, length);
}

void transmit_netinfo_request(dn_sess_t *sess)
{
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoRequest);

	NetinfoRequest_set_ipLocal(msg, sess->ip_local);
	NetinfoRequest_set_macAddr(msg, sess->tun_mac_addr);

	net_send_msg(sess->netc, msg);
}

void transmit_register(netc_t *netc)
{
        size_t nbyte;
	dn_sess_t *session = (dn_sess_t *)netc->ext_ptr;

        DNDSMessage_t *msg;

        DNDSMessage_new(&msg);
        DNDSMessage_set_channel(msg, 0);
        DNDSMessage_set_pdu(msg, pdu_PR_dnm);

        DNMessage_set_seqNumber(msg, 1);
        DNMessage_set_ackNumber(msg, 0);
        DNMessage_set_operation(msg, dnop_PR_authRequest);

        AuthRequest_set_certName(msg, "nib@1", 5);

        nbyte = net_send_msg(netc, msg);
        if (nbyte == -1) {
                JOURNAL_NOTICE("dnc]> malformed message\n", nbyte);
                return;
        }

        JOURNAL_NOTICE("dnc]> sent %i bytes\n", nbyte);
	session->auth = SESS_WAIT_RESPONSE;

        return;
}

/* this is used by P2P */
static void on_connect(netc_t *netc)
{
	dn_sess_t *session = NULL;

	printf("on_connect\n");

        session = (dn_sess_t *)malloc(sizeof(dn_sess_t));

        if (netc->conn_type == NET_P2P_CLIENT) {
                session->type = SESS_TYPE_P2P_CLIENT;
        } else {
                session->type = SESS_TYPE_P2P_SERVER;
        }


        session->auth = SESS_AUTH;
        session->iface = master_sess->iface;
        session->netc = netc;
	netc->ext_ptr = session;
}

// FIXME : still not sure if we should not use on_secure
static void p2p_on_secure(netc_t *netc)
{
	//netc->ext_ptr->auth = SESS_AUTH;
}

static void on_secure(netc_t *netc)
{
	JOURNAL_NOTICE("dnc]> on_secure !");

	dn_sess_t *sess;
	sess = netc->ext_ptr;

	if (sess->auth == SESS_NOT_AUTH) {
		JOURNAL_NOTICE("dnc]> authenticate");
		transmit_register(netc);
	} else {

		transmit_netinfo_request(sess);
	}
}

static void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	dn_sess_t *sess;
	mbuf_t **mbuf_itr;
	pdu_PR pdu;

	mbuf_itr = &netc->queue_msg;
	sess = netc->ext_ptr;

	while (*mbuf_itr != NULL) {

		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;

		DNDSMessage_get_pdu(msg, &pdu);
		switch (pdu) {
			case pdu_PR_dnm:
				dispatch_operation(sess, msg);
				break;

			case pdu_PR_ethernet:
				tunnel_out(sess->iface, msg);
				break;

			default: // Invalid PDU
				terminate(sess);
				return;
		}

		mbuf_del(mbuf_itr, *mbuf_itr);
	}
}

static void on_disconnect(netc_t *netc)
{
	printf("on_disconnect !!\n");
	dn_sess_t *sess;

	sess = netc->ext_ptr;
}

static void dispatch_operation(dn_sess_t *sess, DNDSMessage_t *msg)
{
	dnop_PR operation;
	e_DNDSResult result;

	char dest_addr[16];
	uint32_t port;
	char port_name[6];
	netc_t *p2p_netc = NULL;
	uint8_t state;
	uint8_t mac_dst[6];

	char ip_addr[INET_ADDRSTRLEN];

	DNMessage_get_operation(msg, &operation);

	switch (operation) {

		case dnop_PR_authResponse:

			AuthResponse_get_result(msg, &result);

			if (result == DNDSResult_success) {
				JOURNAL_INFO("dnc]> session authenticated");
				transmit_netinfo_request(sess);
			}
			else if (result == DNDSResult_secureStepUp) {
				JOURNAL_INFO("dnc]> server authentication require step up");
				net_step_up(sess->netc);
			}
			else {
				JOURNAL_ERR("dnc]> unknown AuthResponse result");
			}

			break;

		case dnop_PR_netinfoResponse:

			NetinfoResponse_get_ipAddress(msg, ip_addr);
			printf("got ip address %s\n", ip_addr);

			master_sess = sess; // XXX 
			tun_up(sess->iface->devname, ip_addr);
			sess->auth = SESS_AUTH;

			// FIXME cache the network informations
			break;

		case dnop_PR_p2pResponse:

			P2pResponse_get_macAddrDst(msg, mac_dst);
			P2pResponse_get_ipAddrDst(msg, dest_addr);
			P2pResponse_get_port(msg, &port);
		
			printf("P2pRequest> mac_dst: %x:%x:%x:%x:%x:%x\n", mac_dst[0],mac_dst[1],mac_dst[2],
                                                        mac_dst[3],mac_dst[4],mac_dst[5]);	

			JOURNAL_DEBUG("dnc]> p2p i will act as the %s", (state == NET_P2P_CLIENT ? "client" : "server"));
			JOURNAL_INFO("dnc]> p2p trying to connect to %s on port %d...", dest_addr, port);

			snprintf(port_name, 6, "%d", port);

			printf("dest_addr: %s\n", dest_addr);
			p2p_netc = net_p2p("192.168.1.135", dest_addr, port_name, NET_PROTO_UDT, NET_UNSECURE, state,
						on_connect, p2p_on_secure, on_disconnect, on_input);

			if (p2p_netc != NULL) {
				printf("insert mac %x\n", mac_dst);
				if (ftable_insert(ftable, mac_dst, p2p_netc->ext_ptr)) {
					// TODO : handle error
				}
				else {
					JOURNAL_INFO("dnc]> p2p connected");
				}
			}
			else {
				JOURNAL_INFO("dnc]> p2p unable to connect");
				// TODO : handle error
			}

			break;
                // terminateRequest is a special case since
                // it has no Response message associated with it.
		// simply disconnect the client;
		case dnop_PR_NOTHING:
		default:
			JOURNAL_NOTICE("dsd]> not a valid DNM operation");
		case dnop_PR_terminateRequest:
			// XXX terminate(sess);
			break;
	}
}

int dnc_init(char *server_address, char *server_port)
{
	netc_t *netc;
	dn_sess_t *sess;

	#include "certificates.h"
	passport_t *dnc_ctx_passport;
	dnc_ctx_passport = pki_passport_load_from_memory(dnc_ctx1_cert_pem,
							 dnc_ctx1_privkey_pem,
							 dsd_ctx1_cert_pem);

	netc = net_client(server_address, server_port, NET_PROTO_UDT, NET_SECURE_ADH, dnc_ctx_passport,
		on_disconnect, on_input, on_secure);

	if (netc == NULL ) {
		return -1;
	}

	/* Initialize the forward table */
        ftable = ftable_new(1024, session_itemdup, session_itemrel);

	sess = calloc(1, sizeof(dn_sess_t));
	sess->iface = NULL;
	sess->netc = netc;
	sess->auth = SESS_NOT_AUTH;
	netc->ext_ptr = sess;

	/* Create the tunnel interface now,
	 * so when we register, we can get the interface
	 * mac address needed by the server.
	 */
	sess->iface = netbus_newtun(tunnel_in);
	sess->iface->ext_ptr = sess;
	tun_up(sess->iface->devname, "0.0.0.0");

	/* XXX
	 * if the link is unsecure,
	 * transmit_register(netc);
	 */

	return 0;
}
