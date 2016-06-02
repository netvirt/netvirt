/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <cert.h>
#include <logger.h>
#include <netbus.h>
#include <dnds.h>

#include "control.h"
#include "inet.h"
#include "request.h"
#include "session.h"
#include "switch.h"
#include "vnetwork.h"

static struct switch_cfg *switch_cfg;
static netc_t *switch_netc = NULL;

static void
forward_ethernet(struct session *session, DNDSMessage_t *msg)
{
	size_t	 	 frame_size;
	uint8_t		*frame;
	uint8_t		 macaddr_src[ETHER_ADDR_LEN];
	uint8_t		 macaddr_dst[ETHER_ADDR_LEN];
	uint8_t		 macaddr_dst_type;
	struct session	*session_dst = NULL;
	struct session	*session_src = NULL;
	struct session	*session_list = NULL;

	if (session->state != SESSION_STATE_AUTHED)
		return;

	DNDSMessage_get_ethernet(msg, &frame, &frame_size);

	/* New mac address ? Add it to the lookup table */
	inet_get_mac_addr_src(frame, macaddr_src);
	session_src = ftable_find(session->vnetwork->ftable, macaddr_src);

	if (session_src == NULL) {
		memcpy(session->mac_addr, macaddr_src, ETHER_ADDR_LEN);
		ftable_insert(session->vnetwork->ftable, macaddr_src, session);
		session_src = session;
		session_add_mac(session, macaddr_src);
	}

	/* Lookup the destination */
	inet_get_mac_addr_dst(frame, macaddr_dst);
	macaddr_dst_type = inet_get_mac_addr_type(macaddr_dst);
	session_dst = ftable_find(session->vnetwork->ftable, macaddr_dst);

	if (session_src != NULL && session_dst != NULL &&
		(session_src == session_dst)) {
		/* prevent loops */
		return;
	}

	if (macaddr_dst_type == ADDR_MULTICAST) {
		/* Multicast is not supported yet */
		return;
	}

	/* Switch forwarding */
	if (macaddr_dst_type == ADDR_UNICAST		/* The destination address is unicast */
		&& session_dst != NULL
		&& session_dst->netc != NULL) {		/* AND the session is up */

			/*jlog(L_DEBUG, "forwarding the packet to [%s]", session_dst->ip);*/
			net_send_msg(session_dst->netc, msg);

			int lnk_state = 0;
			lnk_state = linkst_joined(session_src->vnetwork->linkst, session_src->id, session_dst->id);
			if (lnk_state != 1) {
				p2pRequest(session_src, session_dst);
				linkst_join(session_src->vnetwork->linkst, session_src->id, session_dst->id);
			}


	/* Switch flooding */
	} else if (macaddr_dst_type == ADDR_BROADCAST ||	/* This packet has to be broadcasted */
		session_dst == NULL)  {				/* OR the fib session is down */

			session_list = session->vnetwork->session_list;
			while (session_list != NULL) {
				net_send_msg(session_list->netc, msg);
				/*jlog(L_DEBUG, "flooding the packet to [%s]", session_list->ip);*/
				session_list = session_list->next;
			}
	} else {
		jlog(L_WARNING, "unknown packet");
	}
}

void
transmit_netinfo_response(netc_t *netc)
{
	struct session	*session = netc->ext_ptr;

	DNDSMessage_t *msg = NULL;
	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoResponse);

	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
}

void
handle_netinfo_request(struct session *session, DNDSMessage_t *msg)
{
	NetinfoRequest_get_ipLocal(msg, session->ip_local);
	NetinfoRequest_get_macAddr(msg, session->tun_mac_addr);

	jlog(L_NOTICE, "client local ip: %s", session->ip_local);
	jlog(L_NOTICE, "client mac addr: %02x:%02x:%02x:%02x:%02x:%02x",
		session->tun_mac_addr[0],
		session->tun_mac_addr[1],
		session->tun_mac_addr[2],
		session->tun_mac_addr[3],
		session->tun_mac_addr[4],
		session->tun_mac_addr[5]);

	transmit_netinfo_response(session->netc);
}

static void
dispatch_operation(struct session *session, DNDSMessage_t *msg)
{
	dnop_PR operation;
	DNMessage_get_operation(msg, &operation);

	switch (operation) {
	case dnop_PR_provRequest:
		provRequest(session, msg);
		break;

	case dnop_PR_authRequest:
		authRequest(session, msg);
		break;

	case dnop_PR_netinfoRequest:
		handle_netinfo_request(session, msg);
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

static void
on_secure(netc_t *netc)
{
	X509 *cert;
	char *altname = NULL;
	char *cn = NULL;
	struct session *session;
	session = netc->ext_ptr;

	if (session->state != SESSION_STATE_WAIT_STEPUP)
		return;

	/* update node info from peer certificate */
	node_info_destroy(session->node_info);
	cert = SSL_get_peer_certificate(netc->kconn->ssl);
	if ((altname = cert_altname_uri(cert)) == NULL) {
		if ((cn = cert_cname(cert)) == NULL)
			return;
		session->node_info = cn2node_info(cn);
	} else {
		session->node_info = altname2node_info(altname);
	}

	X509_free(cert);

	/* Send a message to acknowledge the client */
	DNDSMessage_t *msg = NULL;
	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_authResponse);

	/* check if the node's uuid is known */
	if (ctable_find(session->vnetwork->atable, session->node_info->uuid) == NULL) {
		AuthResponse_set_result(msg, DNDSResult_noRight);
		jlog(L_ERROR, "authentication failed, invalid certificate");
		goto out;
	} else {
		AuthResponse_set_result(msg, DNDSResult_success);
	}

	/* reWrite network_uuid, it has been destroyed */
	if (session->node_info->v == 1) {
		strncpy(session->node_info->network_uuid, session->vnetwork->uuid, 36);
		session->node_info->network_uuid[36] = '\0';
	}

	/* Set the session as authenticated */
	session->state = SESSION_STATE_AUTHED;

	vnetwork_add_session(session->vnetwork, session);
	update_node_status("1", session->ip, session->node_info->uuid, session->node_info->network_uuid);
	jlog(L_DEBUG, "session id: %d", session->id);
out:
	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);
}

static void
on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	struct session *session;
	mbuf_t **mbuf_itr;
	pdu_PR pdu;

	mbuf_itr = &netc->queue_msg;
	session = (struct session *)netc->ext_ptr;
	if (session->state == SESSION_STATE_PURGE) {
		jlog(L_NOTICE, "purge node: %s", session->cert_name);
		net_disconnect(netc);
		return;
	}

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
			jlog(L_ERROR, "invalid PDU");
			break;
		}
		mbuf_del(mbuf_itr, *mbuf_itr);
	}
}

static void
on_connect(netc_t *netc)
{
	struct session *session = NULL;
	session = session_new();

	if (session == NULL) {
		jlog(L_ERROR, "unable to create a new session");
		net_disconnect(netc);
		return;
	}

	session->ip = strdup(netc->peer->host);
	session->netc = netc;
	netc->ext_ptr = session;

	return;
}

static void
on_disconnect(netc_t *netc)
{
	jlog(L_DEBUG, "disconnect");

	struct session *session = NULL;
	struct mac_list *mac_itr = NULL;

	session = netc->ext_ptr;

	if (session == NULL) {
		return;
	}

	if (session->state == SESSION_STATE_NOT_AUTHED) {
		session_free(session);
		return;
	}

	/* If the ventwork is still valid, update the node in it. */
	if (session->vnetwork != NULL) {

		linkst_disjoin(session->vnetwork->linkst, session->id);

		while (session->mac_list != NULL) {
			mac_itr = session->mac_list;
			session->mac_list = mac_itr->next;
			ftable_erase(session->vnetwork->ftable, mac_itr->mac_addr);
			free(mac_itr);
		}

		ctable_erase(session->vnetwork->ctable, session->node_info->uuid);
		vnetwork_del_session(session->vnetwork, session);
	}

	update_node_status("0", session->ip, session->node_info->uuid, session->node_info->network_uuid);

	session_free(session);

	return;
}

static void
*switch_loop(void *nil)
{
	while (switch_cfg->switch_running) {
		udtbus_poke_queue();
	}

	krypt_fini();

	return NULL;
}

void *
switch_init(void *cfg)
{
	switch_cfg = cfg;
	switch_cfg->switch_running = 1;

	while (switch_cfg->ctrl_initialized == 0)
		sleep(1);

	switch_netc = net_server(switch_cfg->listen_ip, switch_cfg->listen_port, NET_PROTO_UDT, NET_SECURE_ADH, NULL,
		on_connect, on_disconnect, on_input, on_secure);

	if (switch_netc == NULL) {
		jlog(L_ERROR, "net_server failed");
		return NULL;
	}

	pthread_t thread_loop;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(&thread_loop, &attr, switch_loop, NULL);

	return NULL;
}

void
switch_fini()
{
	net_disconnect(switch_netc);
}
