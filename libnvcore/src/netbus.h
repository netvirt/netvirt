/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
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

#ifndef NETBUS_H
#define NETBUS_H

#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dnds.h"
#include "crypto.h"
#include "mbuf.h"
#include "udt.h"

#define NET_PROTO_TCP	0x01
#define NET_PROTO_UDT	0x02

#define NET_CLIENT	0x1
#define NET_SERVER	0x2

#define NET_P2P_CLIENT	1
#define NET_P2P_SERVER	2

#define NET_QUEUE_IN	0x1
#define NET_QUEUE_OUT	0x2

typedef struct netc {

	DNDSMessage_t *msg_dec;		/* Decoded DNDS Message ready to be queued */

	uint8_t *buf_in;		/* Serialize raw input data */
	size_t buf_in_size;		/* Buffer size in memory */
	size_t buf_in_offset;		/* Start of the valid data */
	size_t buf_in_data_size;	/* Data size in the buffer */

	uint8_t *buf_enc;		/* Serialized encoded chunks */
	size_t buf_enc_size;		/* Buffer size in memory */
	size_t buf_enc_data_size;	/* Data size in the buffer */

	mbuf_t *queue_msg;		/* Queue of decoded DNDS Message ready to be processed */
	mbuf_t *queue_out;		/* Queue of encoded DNDS Message ready to be sent */

	struct krypt *kconn;		/* SSL-related security informations */

	uint8_t protocol;		/* Transport protocol { TCP, UDT } */
	uint8_t conn_type;		/* Connection type { SERVER, CLIENT, P2P_CLIENT, P2P_SERVER } */

	peer_t *peer;			/* Low-level peer informations */
	void *ext_ptr;

	void (*on_secure)(struct netc *);
	void (*on_connect)(struct netc *);
	void (*on_disconnect)(struct netc *);
	void (*on_input)(struct netc *);

} netc_t;

int net_get_local_ip(char *ip_local, int len);
void net_step_up(netc_t *netc);
int net_send_msg(netc_t *, DNDSMessage_t *);
void net_disconnect(netc_t *);

void netbus_tcp_init();
int netbus_init();
void netbus_fini();

netc_t *net_client(const char *listen_addr,
			const char *port,
			uint8_t protocol,
			passport_t *passport,
			const char *servername,
			void (*on_disconnect)(netc_t *),
			void (*on_input)(netc_t *),
			void (*on_secure)(netc_t *));

netc_t *net_server(const char *listen_addr,
		const char *port,
		uint8_t protocol,
		passport_t *passport,
		void (*on_connect)(netc_t *),
		void (*on_disconnect)(netc_t *),
		void (*on_input)(netc_t *),
		void (*on_secure)(netc_t *),
		passport_t *(*servername_cb)(const char *));

void net_p2p(const char *listen_addr,
		const char *dest_addr,
		const char *port,
		uint8_t protocol,
		uint8_t state,
		passport_t *passport,
		void (*on_connect)(netc_t *),
		void (*on_secure)(netc_t *),
		void (*on_disconnect)(netc_t *),
		void (*on_input)(netc_t *),
		void *ext_ptr);

#endif /* NETBUS_H */
