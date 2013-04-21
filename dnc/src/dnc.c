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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include <dnds.h>
#include <logger.h>
#include <mbuf.h>
#include <netbus.h>
#include <inet.h>

#include "dnc.h"
#include "session.h"

struct dnc_cfg *g_dnc_cfg;

#if 0
static void dispatch_operation(struct session *session, DNDSMessage_t *msg);

//static ftable_t *ftable;
struct session *master_session;

static int g_shutdown = 0;	/* True if DNC is shutting down */
#if 0
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
	if (session->state != SESSION_STATE_AUTHED) {
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
	 * Otherwise the packet is sent to the server, where it will be switched to the right node.

	FIXME: still in alpha, must become asynchronous

	p2p_session = ftable_find(ftable, macaddr_dst);
	if (p2p_session && p2p_session->state == SESSION_STATE_AUTHED) {
		session = p2p_session;
	}*/
	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
	iface->frame = NULL;
}

static void tunnel_out(iface_t *iface, DNDSMessage_t *msg)
{
	uint8_t *frame;
	size_t frame_size;

	DNDSMessage_get_ethernet(msg, &frame, &frame_size);
	iface->write(iface, frame, frame_size);
}
#endif

void terminate(struct session *session)
{
	session->state = SESSION_STATE_DOWN;
	net_disconnect(session->netc);
	session->netc = NULL;
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
	DNDSMessage_del(msg);
}

void transmit_prov_request(netc_t *netc)
{
	size_t nbyte;
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_provRequest);

	ProvRequest_set_provCode(msg, g_prov_code, strlen(g_prov_code));

	nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
	if (nbyte == -1) {
		jlog(L_NOTICE, "dnc]> malformed message\n", nbyte);
		return;
	}
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

	jlog(L_NOTICE, "dnc]> CN=%s", subj);
        AuthRequest_set_certName(msg, subj, strlen(subj));

        nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
        if (nbyte == -1) {
                jlog(L_NOTICE, "dnc]> malformed message: %d\n", nbyte);
                return;
        }

	session->state = SESSION_STATE_WAIT_ANSWER;

        return;
}

static void on_input(netc_t *netc);
static void on_secure(netc_t *netc);

static void on_disconnect(netc_t *netc)
{
	jlog(L_NOTICE, "dnc]> disconnected...\n");

	netc_t *retry_netc = NULL;
	struct session *session;

	session = netc->ext_ptr;
	session->state = SESSION_STATE_DOWN;

	do {
		sleep(5);

		jlog(L_NOTICE, "dnc]> connection retry...\n");

		retry_netc = net_client(session->server_address,
		session->server_port, NET_PROTO_UDT, NET_SECURE_ADH,
		session->passport, on_disconnect, on_input, on_secure);

		if (retry_netc) {
			session->state = SESSION_STATE_NOT_AUTHED;
			session->netc = retry_netc;
			retry_netc->ext_ptr = session;
			return;
		}

	} while (!g_shutdown);
}

/* only used by P2P */
static void on_connect(netc_t *netc)
{
	struct session *session = NULL;
        session = malloc(sizeof(struct session));

        if (netc->conn_type == NET_P2P_CLIENT) {
                session->type = SESSION_TYPE_P2P_CLIENT;
        } else {
                session->type = SESSION_TYPE_P2P_SERVER;
        }

        session->state = SESSION_STATE_AUTHED;
        session->iface = master_session->iface;
        session->netc = netc;
	netc->ext_ptr = session;
}

static void p2p_on_secure(netc_t *netc)
{
}

static void on_secure(netc_t *netc)
{
	jlog(L_NOTICE, "dnc]> connection secured");

	struct session *session;
	session = netc->ext_ptr;

	if (session->state == SESSION_STATE_NOT_AUTHED) {

		/* XXX is there a better way to detect that we
		 * have no certificate yet ? */
		if (session->passport == NULL) {
			jlog(L_NOTICE, "dnc]> Provisioning mode...");
			transmit_prov_request(netc);
		}
		else {
			transmit_register(netc);
		}
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

	size_t length;
	char *certificate = NULL;
	char *certificatekey = NULL;
	char *trusted_authority = NULL;
        char ipAddress[INET_ADDRSTRLEN];

	FILE *fp = NULL;

	DNMessage_get_operation(msg, &operation);

	/* TODO all cases must be handled in seperate functions */

	switch (operation) {

		case dnop_PR_provResponse:

			ProvResponse_get_certificate(msg, &certificate, &length);

			fp = fopen(g_certificate, "w");
			fwrite(certificate, 1, strlen(certificate), fp);
			fclose(fp);

			ProvResponse_get_certificateKey(msg, &certificatekey, &length);
			fp = fopen(g_privatekey, "w");
			fwrite(certificatekey, 1, strlen(certificatekey), fp);
			fclose(fp);

			ProvResponse_get_trustedCert(msg, &trusted_authority, &length);
			fp = fopen(g_trusted_authority, "w");
			fwrite(trusted_authority, 1, strlen(trusted_authority), fp);
			fclose(fp);

			ProvResponse_get_ipAddress(msg, ipAddress);
			printf("dnc]> ip address: %s\n", ipAddress);
			fp = fopen("/etc/dnds/dnc.ip", "w");
			fprintf(fp, "%s", ipAddress);
			fclose(fp);


			session->passport = pki_passport_load_from_file(g_certificate,
							 g_privatekey,
							 g_trusted_authority);


			krypt_add_passport(session->netc->kconn, session->passport);
			transmit_register(session->netc);

			break;

		case dnop_PR_authResponse:

			AuthResponse_get_result(msg, &result);

			if (result == DNDSResult_success) {
				jlog(L_NOTICE, "dnc]> session authenticated");
				transmit_netinfo_request(session);
			}
			else if (result == DNDSResult_secureStepUp) {
				jlog(L_NOTICE, "dnc]> server authentication require step up");
				net_step_up(session->netc);
			}
			else {
				jlog(L_NOTICE, "dnc]> unknown AuthResponse result (%i)", result);
			}

			break;

		case dnop_PR_netinfoResponse:

			master_session = session;

			fp = fopen("/etc/dnds/dnc.ip", "r");
			if (fp == NULL) {
				jlog(L_ERROR, "/etc/dnds/dnc.ip doesn't exist, please reprovision your client");
				exit(-1);
				return;
			}
			fscanf(fp, "%s", ipAddress);
			fclose(fp);

			tun_up(session->iface->devname, ipAddress);
			session->state = SESSION_STATE_AUTHED;

			break;

		case dnop_PR_p2pRequest:

			P2pRequest_get_macAddrDst(msg, mac_dst);
			P2pRequest_get_ipAddrDst(msg, dest_addr);
			P2pRequest_get_port(msg, &port);

			snprintf(port_name, 6, "%d", port);
			p2p_netc = net_p2p("0.0.0.0", dest_addr, port_name, NET_PROTO_UDT, NET_UNSECURE, state,
						on_connect, p2p_on_secure, on_disconnect, on_input);

			if (p2p_netc != NULL) {
				jlog(L_NOTICE, "dnc]> p2p connected");
				//ftable_insert(ftable, mac_dst, p2p_netc->ext_ptr);
			} else {
				jlog(L_NOTICE, "dnc]> p2p unable to connect");
			}

			break;

                /* `terminateRequest` is a special case since it has no
		 * response message associated with it, simply disconnect the client.
		 */
		case dnop_PR_NOTHING:
		default:
			jlog(L_NOTICE, "dnc]> not a valid DNM operation");
		case dnop_PR_terminateRequest:
			terminate(session);
			break;
	}
}

void dnc_fini(void *ext_ptr)
{
	g_shutdown = 1;
}
#endif

int dnc_init(struct dnc_cfg *dnc_cfg)
{
	struct session *session;

	g_dnc_cfg = dnc_cfg;
	session = calloc(0, sizeof(struct session));
	session->passport = pki_passport_load_from_file(
		dnc_cfg->certificate, dnc_cfg->privatekey, dnc_cfg->trusted_cert);

/*
	if (session->passport == NULL && dnc_cfg->prov_code == NULL) {
		jlog(L_ERROR, "dnc]> Must provide a provisioning code: ./dnc -p ...");
		return -1;
	}
*/

/*
	session->netc = net_client(dnc_cfg->server_address, dnc_cfg->server_port,
			NET_PROTO_UDT, NET_SECURE_ADH, session->passport,
			on_disconnect, on_input, on_secure);

	if (session->netc == NULL) {
		free(session);
		return -1;
	}
*/
	session->tapcfg = NULL;
	session->state = SESSION_STATE_NOT_AUTHED;
//	session->netc->ext_ptr = session;

	/* Create the tunnel interface now, so when we register
	 * we can extract the interface mac address needed by the server.
	 */
	session->tapcfg = tapcfg_init();
	if (session->tapcfg == NULL) {
		jlog(L_ERROR, "dnc]> tapcfg_init failed");
		return -1;
	}

	if (tapcfg_start(session->tapcfg, NULL, 1) < 0) {
		jlog(L_ERROR, "dnc]> tapcfg_start failed");
		return -1;
	}

	session->devname = tapcfg_get_ifname(session->tapcfg);
	jlog(L_DEBUG, "dnc]> devname: %s", session->devname);

	return 0;
}
