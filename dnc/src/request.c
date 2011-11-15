/*
 * request.c: Request handler API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds/journal.h>

#include "request.h"

void request_p2p(netc_t *netc, uint8_t *mac_src, uint8_t *mac_dst)
{
	DNDSMessage_t *msg;
	size_t nbyte;

	JOURNAL_DEBUG("dnc]> asking rendezvous with %02x:%02x:%02x:%02x:%02x:%02x",
			mac_dst[0],
			mac_dst[1],
			mac_dst[2],
			mac_dst[3],
			mac_dst[4],
			mac_dst[5]);

	JOURNAL_DEBUG("dnc]> asking rendezvous with %02x:%02x:%02x:%02x:%02x:%02x",
			mac_src[0],
			mac_src[1],
			mac_src[2],
			mac_src[3],
			mac_src[4],
			mac_src[5]);

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_p2pRequest);

	// TODO - fetch local ip
	char local_ip[16];
	inet_get_local_ip(local_ip, 16);
	P2pRequest_set_ipLocal(msg, local_ip);
	P2pRequest_set_macAddrSrc(msg, mac_src);
	P2pRequest_set_macAddrDst(msg, mac_dst);

	nbyte = net_send_msg(netc, msg);
}
