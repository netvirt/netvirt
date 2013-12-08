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

#ifndef P2P_H
#define P2P_H

#include <session.h>

struct p2p_arg {
	struct session *session;
	char ip_dst[INET_ADDRSTRLEN];
	uint8_t mac_dst[ETHER_ADDR_LEN];
	uint32_t port;
};

struct session *p2p_find_session(uint8_t *eth_frame);
void *op_p2p_request(void *ptr);
void p2p_init();

#endif
