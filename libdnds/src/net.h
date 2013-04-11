#ifndef DNDS_NET_H
#define DNDS_NET_H

#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dnds.h"
#include "krypt.h"
#include "mbuf.h"
#include "netbus.h"

#define NET_PROTO_TCP	0x01
#define NET_PROTO_UDT	0x02

#define NET_CLIENT	0x1
#define NET_SERVER	0x2
#define NET_P2P_CLIENT	0x4
#define NET_P2P_SERVER	0x8

#define NET_UNSECURE		0X01
#define NET_SECURE_ADH		0x02
#define NET_SECURE_RSA		0x04

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
	uint8_t security_level;		/* Security level set { UNSECURE, ADH, RSA } */

	uint8_t protocol;		/* Transport protocol { TCP, UDT } */
	uint8_t conn_type;		/* Connection type { SERVER, CLIENT, P2P_CLIENT, P2P_SERVER } */

	peer_t *peer;			/* Low-level peer informations */
	void *ext_ptr;

	void (*on_secure)(struct netc *);
	void (*on_connect)(struct netc *);
	void (*on_disconnect)(struct netc *);
	void (*on_input)(struct netc *);

} netc_t;

void net_step_up(netc_t *netc);
int net_send_msg(netc_t *, DNDSMessage_t *);
void net_disconnect(netc_t *);

netc_t *net_client(const char *listen_addr,
			const char *port,
			uint8_t protocol,
			uint8_t secure_flag,
			passport_t *passport,
			void (*on_disconnect)(netc_t *),
			void (*on_input)(netc_t *),
			void (*on_secure)(netc_t *));

int net_server(const char *listen_addr,
		const char *port,
		uint8_t protocol,
		uint8_t security_level,
		passport_t *passport,
		void (*on_connect)(netc_t *),
		void (*on_disconnect)(netc_t *),
		void (*on_input)(netc_t *),
		void (*on_secure)(netc_t *));

netc_t *net_p2p(const char *listen_addr,
		const char *dest_addr,
		const char *port,
		uint8_t protocol,
		uint8_t security_level,
		uint8_t state,
		void (*on_connect)(netc_t *),
		void (*on_secure)(netc_t *),
		void (*on_disconnect)(netc_t *),
		void (*on_input)(netc_t *));

#endif /* DNDS_NET_H */
