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

#include <cli.h>
#include <dnds.h>
#include <event.h>
#include <journal.h>
#include <mbuf.h>
#include <net.h>
#include <netbus.h>
#include <pki.h>
#include <tun.h>
#include <inet.h>
#include <ftable.h>

#include "dnc.h"
#include "session.h"

static char const module_name[] = "dnc";

extern cli_server_t *dnc_cli_server;

static int handle_connect(cli_entry_t *, int, cli_args_t *);
static int handle_disconnect(cli_entry_t *, int, cli_args_t *);
static int handle_show_peer(cli_entry_t *, int, cli_args_t *);

static cli_entry_t commands[] = {
	CLI_ENTRY(handle_connect, "Connect to a dynamic network controller"),
	CLI_ENTRY(handle_disconnect, "Disconnect from dynamic network"),
	CLI_ENTRY(handle_show_peer, "Show peer connection status"),
};

static void dispatch_operation(struct session *session, DNDSMessage_t *msg);

static ftable_t *ftable;
struct session *master_session;

static int g_shutdown = 0;	/* True if DNC is shutting down */

/* TODO must be part of a config->members */
char *g_certificate = NULL;
char *g_privatekey = NULL;
char *g_trusted_authority = NULL;
char *g_prov_code = NULL;

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
	 * Otherwise the packet is sent to the server, where it will be switched to the right node.

	FIXME: still in alpha, must become asynchronous

	p2p_session = ftable_find(ftable, macaddr_dst);
	if (p2p_session && p2p_session->status == SESSION_STATUS_AUTHED) {
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

void terminate(struct session *session)
{
	session->status = SESSION_STATUS_DOWN;
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

	jlog(L_NOTICE, "dnc> my common name: %s\n", subj);
        AuthRequest_set_certName(msg, subj, strlen(subj));

        nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
        if (nbyte == -1) {
                jlog(L_NOTICE, "dnc]> malformed message: %d\n", nbyte);
                return;
        }

        jlog(L_NOTICE, "dnc]> sent %i bytes\n", nbyte);
	session->status = SESSION_STATUS_WAIT_ANSWER;

        return;
}

static void on_input(netc_t *netc);
static void on_secure(netc_t *netc);

static void on_disconnect(netc_t *netc)
{
	jlog(L_NOTICE, "on_disconnect !!\n");

	netc_t *retry_netc = NULL;
	struct session *session;

	session = netc->ext_ptr;
	session->status = SESSION_STATUS_DOWN;

	do {
		sleep(5);

		jlog(L_NOTICE, "connection retry...\n");

		retry_netc = net_client(session->server_address,
		session->server_port, NET_PROTO_UDT, NET_SECURE_ADH,
		session->passport, on_disconnect, on_input, on_secure);

		if (retry_netc) {
			session->status = SESSION_STATUS_NOT_AUTHED;
			session->netc = retry_netc;
			retry_netc->ext_ptr = session;
			return;
		}

	} while (!g_shutdown);
}

/* only used by P2P */
static void on_connect(netc_t *netc)
{
	jlog(L_NOTICE, "on_connect\n");

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
	jlog(L_NOTICE, "dnc]> on_secure !");

	struct session *session;
	session = netc->ext_ptr;

	if (session->status == SESSION_STATUS_NOT_AUTHED) {

		/* XXX is there a better way to detect that we
		 * have no certificate yet ? */
		if (session->passport == NULL) {
			jlog(L_NOTICE, "Provisioning mode !\n");
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
			jlog(L_NOTICE, "certkey length: %d\n", length);
			fp = fopen(g_privatekey, "w");
			fwrite(certificatekey, 1, strlen(certificatekey), fp);
			fclose(fp);

			ProvResponse_get_trustedCert(msg, &trusted_authority, &length);
			fp = fopen(g_trusted_authority, "w");
			fwrite(trusted_authority, 1, strlen(trusted_authority), fp);
			fclose(fp);

			ProvResponse_get_ipAddress(msg, ipAddress);
			printf("ipAddress: %s\n", ipAddress);
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

			NetinfoResponse_get_ipAddress(msg, ip_addr);
			jlog(L_NOTICE, "dnc]> got ip address %s\n", ip_addr);

			master_session = session;

			fp = fopen("/etc/dnds/dnc.ip", "r");
			fscanf(fp, "%s", ipAddress);
			fclose(fp);


			tun_up(session->iface->devname, ipAddress);


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
				jlog(L_NOTICE, "dnc]> p2p connected");
				ftable_insert(ftable, mac_dst, p2p_netc->ext_ptr);
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

static int handle_connect(cli_entry_t *entry, int cmd, cli_args_t *args)
{
	netc_t *netc;

	switch (cmd) {
	case CLI_INIT:
		entry->command = "dnc connect";
		entry->usage =
		    "Usage: dnc connect\n"
		    "       Connect to dynamic network using config file.";
		return CLI_RETURN_SUCCESS;
	}

	if (args->argc)
		return CLI_RETURN_SHOWUSAGE;

	if (master_session) {
		if (master_session->status != SESSION_STATUS_DOWN) {
			cli_print(args->out, "Already connected\n");
			return CLI_RETURN_FAILURE;
		}

		netc = net_client(master_session->server_address,
		    master_session->server_port, NET_PROTO_UDT,
		    NET_SECURE_ADH, master_session->passport,
		    on_disconnect, on_input, on_secure);

                if (!netc) {
			cli_print(args->out, "Cannot establish connection\n");
			return CLI_RETURN_FAILURE;
		}

		master_session->status = SESSION_STATUS_NOT_AUTHED;
		master_session->netc = netc;
		netc->ext_ptr = master_session;

		return CLI_RETURN_SUCCESS;
	}

	cli_print(args->out, "Cannot get session information\n");
	return CLI_RETURN_FAILURE;
}

static int handle_disconnect(cli_entry_t *entry, int cmd, cli_args_t *args)
{
	switch (cmd) {
	case CLI_INIT:
		entry->command = "dnc disconnect";
		entry->usage =
		    "Usage: dnc disconnect\n"
		    "       Disconnect from dynamic network.";
		return CLI_RETURN_SUCCESS;
	}

	if (args->argc)
		return CLI_RETURN_SHOWUSAGE;

	if (master_session && master_session->status != SESSION_STATUS_DOWN) {
		terminate(master_session);
		return CLI_RETURN_SUCCESS;
	}

	cli_print(args->out, "Not connected yet\n");
	return CLI_RETURN_FAILURE;
}

static int handle_show_peer(cli_entry_t *entry, int cmd, cli_args_t *args)
{
	switch (cmd) {
	case CLI_INIT:
		entry->command = "dnc show peer";
		entry->usage =
		    "Usage: dnc show peer\n"
		    "       Display the peering table";
		return CLI_RETURN_SUCCESS;
	}

	if (args->argc)
		return CLI_RETURN_SHOWUSAGE;

	return CLI_RETURN_SUCCESS;
}

void dnc_fini(void *ext_ptr)
{
	g_shutdown = 1;
}

int dnc_init(char *server_address, char *server_port, char *prov_code,
		char *certificate, char *privatekey, char *trusted_authority)
{
	netc_t *netc;
	struct session *session;

	if (dnc_cli_server)
		cli_register_entry(&(dnc_cli_server->command_list),
		    module_name, commands, CLI_ENTRY_COUNT(commands));

	session = calloc(1, sizeof(struct session));
	session->passport = pki_passport_load_from_file(certificate,
							 privatekey,
							 trusted_authority);

	if (session->passport == NULL && prov_code == NULL) {
		jlog(L_ERROR, "dnc]> Must provide a provisioning code: ./dnc -p ...");
		return -1;
	}

	/* XXX these var should be part of a global
	 * config->certificate...
	 */
	g_certificate = certificate;
	g_privatekey = privatekey;
	g_trusted_authority = trusted_authority;
	g_prov_code = prov_code;

	session->server_address = server_address;
	session->server_port = server_port;

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

	event_register(EVENT_EXIT, "dnc]> dnc_fini", dnc_fini, PRIO_AGNOSTIC);

	return 0;
}
