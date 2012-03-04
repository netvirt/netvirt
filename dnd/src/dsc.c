/*
 * dsc.c: Directory Service Client
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds/dnds.h>
#include <dnds/journal.h>
#include <dnds/net.h>
#include <dnds/pki.h>

#include "dsc.h"

netc_t *netc; /* Temporary here */

int transmit_peerconnectinfo(e_ConnectState state, char *ipAddress, char *certName)
{
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

        DSMessage_set_seqNumber(msg, 0);
        DSMessage_set_ackNumber(msg, 0);
        DSMessage_set_operation(msg, dsop_PR_peerConnectInfo);

        PeerConnectInfo_set_certName(msg, certName, strlen(certName));
        PeerConnectInfo_set_ipAddr(msg, ipAddress);
        PeerConnectInfo_set_state(msg, state);  

	net_send_msg(netc, msg);
}

static void on_secure(netc_t *netc)
{
	JOURNAL_DEBUG("dsc on secure");
}

static void on_input(netc_t *netc)
{

}

static void on_connect(netc_t *netc)
{

}


static void on_disconnect(netc_t *netc)
{

}

void dsc_fini(void *ext_ptr)
{

}

int dsc_init(char *ip_address, char *port, char *certificate, char *privatekey, char *trusted_authority)
{

	passport_t *dnd_passport;
	dnd_passport = pki_passport_load_from_file(certificate, privatekey, trusted_authority);

	netc = net_client(ip_address, port, NET_PROTO_UDT, NET_SECURE_RSA, dnd_passport,
				on_disconnect, on_input, on_secure);

	if (netc == NULL) {
		JOURNAL_NOTICE("dnd]> failed to connect to the Directory Service :: %s:%i\n", __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

