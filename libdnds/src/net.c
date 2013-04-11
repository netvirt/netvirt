/*
 * net.c: Network abstraction layer API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "dnds.h"
#include "journal.h"
#include "net.h"
#include "netbus.h"
#include "udtbus.h"

static void net_connection_free(netc_t *netc)
{
	if (netc != NULL) {

		if (netc->kconn != NULL) {
			free(netc->kconn->buf_decrypt);
			free(netc->kconn->buf_encrypt);
			free(netc->kconn);
		}

		DNDSMessage_del(netc->msg_dec);
		free(netc->buf_in);
		free(netc->buf_enc);
		mbuf_free(&netc->queue_msg);
		mbuf_free(&netc->queue_out);
		free(netc);
	}
}

static netc_t *net_connection_new(uint8_t security_level)
{
	netc_t *netc;

	netc = calloc(1, sizeof(netc_t));
	if (netc == NULL) {
		return NULL;
	}

	if (security_level > NET_UNSECURE) {

		netc->kconn = calloc(1, sizeof(krypt_t));
		if (netc->kconn == NULL) {
			net_connection_free(netc);
			return NULL;
		}

		netc->kconn->ssl = NULL;
		netc->kconn->ctx = NULL;
		netc->kconn->cert_name = NULL;
		netc->kconn->internal_bio = NULL;
		netc->kconn->network_bio = NULL;
		netc->kconn->status = KRYPT_NOINIT;

		netc->kconn->buf_decrypt = calloc(1, 1000000);	// XXX dynamic buffer
		netc->kconn->buf_decrypt_size = 1000000;
		netc->kconn->buf_decrypt_data_size = 0;

		netc->kconn->buf_encrypt = calloc(1, 1000000);	// XXX dynamic buffer
		netc->kconn->buf_encrypt_size = 1000000;
		netc->kconn->buf_encrypt_data_size = 0;
	}

	netc->buf_enc = malloc(1000000);	// XXX dynamic buffer
	netc->buf_enc_size = 1000000;	// XXX initialization size
	netc->buf_enc_data_size = 0;

	netc->buf_in = malloc(1000000);	// XXX dynamic buffer
	netc->buf_in_size = 1000000;	// XXX initialization size
	netc->buf_in_offset = 0;
	netc->buf_in_data_size = 0;

	netc->queue_msg = NULL;
	netc->queue_out = NULL;

	return netc;
}

// send data that SSL generated during read/write/handshake operations.
static void net_do_krypt(netc_t *netc)
{
	ssize_t nbyte;

	if (netc->kconn->buf_encrypt_data_size > 0) {

		nbyte = netc->peer->send(netc->peer, netc->kconn->buf_encrypt, netc->kconn->buf_encrypt_data_size);
		if (nbyte == -1) {
			return;
		}

		if (nbyte >= 0)
			netc->kconn->buf_encrypt_data_size = 0; // XXX adjust with offset ?
	}
}

// queue fully decoded DNDS messages
static void net_queue_msg(netc_t *netc, DNDSMessage_t *msg)
{
	mbuf_t *mbuf;

	// the size doesn't matter, mbuf reference the message only,
	// the external free function is used to release the DNDS message
	mbuf = mbuf_new((const void *)msg, 0, MBUF_BYREF, DNDSMessage_del);
	mbuf_add(&netc->queue_msg, mbuf);

	netc->msg_dec = NULL;
}

// queue data ready to be sent
static void net_queue_out(netc_t *netc, uint8_t *buf, size_t data_size)
{
	mbuf_t *mbuf;

	mbuf = mbuf_new((const void *)buf, data_size, MBUF_BYVAL, NULL);
	mbuf_add(&netc->queue_out, mbuf);
}

// serialize data coming from the low-level network layer
static void serialize_buf_in(netc_t *netc, const void *buf, size_t data_size)
{
	memmove(netc->buf_in + netc->buf_in_offset + netc->buf_in_data_size, buf, data_size);
	netc->buf_in_data_size += data_size;
}

// serialize_buf_enc() arguments are placed in a non-standard way,
// ber_decoded() use it as a callback to bufout decoded chunks.
static int serialize_buf_enc(const void *buf, size_t data_size, void *ext_ptr)
{
	netc_t *netc;
	netc = (netc_t *)ext_ptr;

	memmove(netc->buf_enc + netc->buf_enc_data_size, buf, data_size);
	netc->buf_enc_data_size += data_size;

	return 0;
}

static int net_flush_queue_out(netc_t *netc)
{
	size_t nbyte = 0;

	peer_t *peer = NULL;
	mbuf_t *mbuf_itr = NULL;

	peer = (peer_t *)netc->peer;
	mbuf_itr = netc->queue_out;

	while (mbuf_itr != NULL) {
		nbyte = peer->send(peer, mbuf_itr->ext_buf, mbuf_itr->ext_size);
		if (nbyte == -1) {
			break;
		}
		mbuf_itr = mbuf_itr->next;
	}

	mbuf_free(&netc->queue_out);
	return nbyte;
}

static int net_decode_msg(netc_t *netc)
{
	asn_dec_rval_t dec;

	if (netc->buf_in_data_size == 0)
		return 0;

	do {
		dec = ber_decode(0, &asn_DEF_DNDSMessage,
			(void **)&netc->msg_dec, netc->buf_in + netc->buf_in_offset, netc->buf_in_data_size);

		if (dec.code == RC_WMORE) {
			// decrease the data size according to the consumed bytes
			netc->buf_in_data_size -= dec.consumed;

			// move the start of the data
			if (netc->buf_in_data_size == 0)
				netc->buf_in_offset = 0;
			else
				netc->buf_in_offset += dec.consumed;

			return 0;
		}
		else if (dec.code == RC_FAIL) {
			jlog(L_NOTICE, "net]> ber_decode returned RC_FAIL after consuming %i bytes", dec.consumed);

			netc->buf_in_data_size = 0;
			netc->buf_in_offset = 0;

			return -1;
		}
		else if (dec.code == RC_OK) {

			// queue the fully decoded message
			net_queue_msg(netc, netc->msg_dec);

			// decrease the data size according to the consumed bytes
			netc->buf_in_data_size -= dec.consumed;

			// move the start of the data
			if (netc->buf_in_data_size == 0)
				netc->buf_in_offset = 0;
			else
				netc->buf_in_offset += dec.consumed;
		}

	} while (dec.code == RC_OK && netc->buf_in_data_size);

	// RC_OK
	return 0;
}

static void net_on_input(peer_t *peer)
{
	int ret = 0;
	int nbyte = 0;
	netc_t *netc = NULL;


	netc = peer->ext_ptr;
	peer->buffer_data_len = peer->recv(peer);

	if (netc->security_level > NET_UNSECURE
		&& netc->kconn->status == KRYPT_HANDSHAKE) {


		ret = krypt_do_handshake(netc->kconn, peer->buffer, peer->buffer_data_len);
		peer->buffer_data_len = 0;
		if (ret == 0) {				// handshake successfull

			net_do_krypt(netc);
			netc->on_secure(netc);		// inform upper-layer

			// Handle the fact that we can receive handshake data
			// and DNDS Messages at the same time from the underlying
			// network buffer.
			char peek;
			ret = SSL_peek(netc->kconn->ssl, &peek, 1);
			if (ret == 1) {
				// There is still data in the SSL object,
				// continue further to process pending data.
			}
			else {
				return;
			}
		}
		else if (ret == 1) {			// need more data to continue
			net_do_krypt(netc);
			return;
		}
		else if (ret == -1) {			// handshake failed
			net_do_krypt(netc);
			netc->on_disconnect(netc);	// inform upper-layer
			peer->disconnect(peer);		// inform lower-layer
			net_connection_free(netc);
			return;
		}

		// handshake flow ends here if no more data has to be processed
	}

	if (netc->security_level > NET_UNSECURE
		&& netc->kconn->status == KRYPT_SECURE) {

		int peek = 0; // buffer to hold the byte we are peeking at
		int state_p = 0;
		do {
			nbyte = krypt_push_encrypted_data(netc->kconn, peer->buffer + peer->buffer_offset,										peer->buffer_data_len);

			if (nbyte > 0 && nbyte < peer->buffer_data_len) {
				peer->buffer_data_len -= nbyte;
				peer->buffer_offset += nbyte;
			}
			else{
				peer->buffer_data_len = 0;
				peer->buffer_offset = 0;
			}

			ret = krypt_decrypt_buf(netc->kconn, peer->buffer, peer->buffer_data_len);
			if (ret == 0) {
				serialize_buf_in(netc, netc->kconn->buf_decrypt, netc->kconn->buf_decrypt_data_size);
				netc->kconn->buf_decrypt_data_size = 0; // mark the buffer as empty
				net_do_krypt(netc);
				state_p = SSL_peek(netc->kconn->ssl, &peek, 1);
			}

			// decryption doesn't fail and (SSL data pending or data to feed to BIO)
		} while (ret == 0 && (state_p == 1 || peer->buffer_data_len > 0));
	}
	else if (netc->security_level == NET_UNSECURE) {

		serialize_buf_in(netc, peer->buffer, peer->buffer_data_len);
	}

	ret = net_decode_msg(netc);
	if (ret == -1) {
		netc->on_disconnect(netc);	// inform upper-layer
		peer->disconnect(peer);		// inform lower-layer
		net_connection_free(netc);
	}
	else {
		if (mbuf_count(netc->queue_msg) > 0)
			netc->on_input(netc);
	}
}

static void net_on_disconnect(peer_t *peer)
{
	netc_t *netc = NULL;
	netc = (netc_t *)peer->ext_ptr;

	if (netc != NULL) {
		// inform upper-layer
		if (netc->on_disconnect) {
			netc->on_disconnect(netc);
		}

		jlog(L_NOTICE, "net]> on disconnect");

		peer->ext_ptr = NULL;
		net_connection_free(netc);
	}
	else {
		jlog(L_ERROR, "net]> on disconnect: netc is NULL");
	}
}

static void net_on_connect(peer_t *peer)
{
	int ret;
	netc_t *netc, *new_netc;

	netc = peer->ext_ptr;

	// the new connection inherit the security level of his parent
	new_netc = net_connection_new(netc->security_level);
	if (new_netc == NULL) {
		peer->disconnect(peer);
		return;
	}

	new_netc->on_secure = netc->on_secure;
	new_netc->on_connect = netc->on_connect;
	new_netc->on_disconnect = netc->on_disconnect;
	new_netc->on_input = netc->on_input;
	new_netc->protocol = netc->protocol;
	new_netc->conn_type = NET_SERVER;

	peer->ext_ptr = new_netc;
	new_netc->peer = peer;

	new_netc->security_level = netc->security_level;
	if (netc->security_level > NET_UNSECURE) {

		// FIXME net and krypt should share constants
		int krypt_security_level;
		if (netc->security_level == NET_SECURE_ADH)
			krypt_security_level = KRYPT_ADH;
		else
			krypt_security_level = KRYPT_RSA;

		new_netc->kconn->passport = netc->kconn->passport;

		ret = krypt_secure_connection(new_netc->kconn, KRYPT_TLS, KRYPT_SERVER, krypt_security_level);
	}

	new_netc->on_connect(new_netc);
	if (netc->security_level == NET_UNSECURE)
		new_netc->on_secure(new_netc);
}

void net_step_up(netc_t *netc)
{
	krypt_set_rsa(netc->kconn);		// set security level to RSA
	SSL_renegotiate(netc->kconn->ssl);	// move the SSL connection into renegotiation state

	if (netc->conn_type == NET_CLIENT) {	// Client send ClientHello

		krypt_do_handshake(netc->kconn, NULL, 0);
		net_do_krypt(netc);
	}

	krypt_set_renegotiate(netc->kconn);	// set handshake mode
}

int net_send_msg(netc_t *netc, DNDSMessage_t *msg)
{
	asn_enc_rval_t ec;
	peer_t *peer = NULL;
	size_t nbyte;
	int ret;

	ec = der_encode(&asn_DEF_DNDSMessage, msg, serialize_buf_enc, netc);
	if (ec.encoded == -1) {
		netc->buf_enc_data_size = 0;	// mark the buffer as empty
		jlog(L_ERROR, "net]> DER encoder failed at field '%s'", ec.failed_type->name);
		return -1;
	}

	if (netc->security_level > NET_UNSECURE
		&& netc->kconn->status != KRYPT_SECURE) {

		jlog(L_ERROR, "netc]> the network connection is not yet secure");
		return -1;
	}

	if (netc->security_level > NET_UNSECURE
		&& netc->kconn->status == KRYPT_SECURE) {

		do {
			ret = krypt_encrypt_buf(netc->kconn, netc->buf_enc, netc->buf_enc_data_size);
			net_queue_out(netc, netc->kconn->buf_encrypt, netc->kconn->buf_encrypt_data_size);
		} while (ret == -1); /* SSL BIO buffer is full ! flush it, and write again */
		netc->kconn->buf_encrypt_data_size = 0;

	}
	else {
		net_queue_out(netc, netc->buf_enc, netc->buf_enc_data_size);
	}


	netc->buf_enc_data_size = 0; // mark buffer as empty
	nbyte = net_flush_queue_out(netc);

	return nbyte;
}

void net_disconnect(netc_t *netc)
{
	netc->peer->ext_ptr = NULL;

	// Inform the lower-layer
	if (netc->peer && netc->peer->disconnect)
		netc->peer->disconnect(netc->peer);

	net_connection_free(netc);
}


netc_t *net_client(const char *listen_addr,
			const char *port,
			uint8_t protocol,
			uint8_t security_level,
			passport_t *passport,
			void (*on_disconnect)(netc_t *),
			void (*on_input)(netc_t *),
			void (*on_secure)(netc_t *))
{
	int ret;
	netc_t *netc = NULL;

	netc = net_connection_new(security_level);
	if (netc == NULL) {
	        return NULL;
	}

	netc->protocol = protocol;
	netc->on_secure = on_secure;
	netc->on_disconnect = on_disconnect;
	netc->on_input = on_input;
	netc->conn_type = NET_CLIENT;
	netc->security_level = security_level;

	if (security_level > NET_UNSECURE)
		krypt_add_passport(netc->kconn, passport);

	switch (protocol) {
		case NET_PROTO_TCP:
			netc->peer = netbus_tcp_client(listen_addr,
			    atoi(port), net_on_disconnect, net_on_input);
			break;

		case NET_PROTO_UDT:
			netc->peer = udtbus_client(listen_addr, port,
			    net_on_disconnect, net_on_input);
			break;

		default:
			jlog(L_NOTICE, "net> unknown protocol specified :: %s:%i", __FILE__, __LINE__);
			net_connection_free(netc);
			return NULL;
	}

	if (netc->peer == NULL) {
		jlog(L_NOTICE, "net]> client initialization failed :: %s:%i", __FILE__, __LINE__);
		net_connection_free(netc);
		return NULL;
	}

	netc->peer->ext_ptr = netc;

	if (security_level > NET_UNSECURE) {

		// FIXME net and krypt should share constants
		int krypt_security_level;
		if (netc->security_level == NET_SECURE_ADH)
			krypt_security_level = KRYPT_ADH;
		else
			krypt_security_level = KRYPT_RSA;

		ret = krypt_secure_connection(netc->kconn, KRYPT_TLS, KRYPT_CLIENT, krypt_security_level);
		if (ret < 0) {
			jlog(L_NOTICE, "net]> securing client connection failed :: %s:%i", __FILE__, __LINE__);
			net_connection_free(netc);
			return NULL;
		}

		krypt_do_handshake(netc->kconn, NULL, 0);
		net_do_krypt(netc);
	}

	return netc;
}

int net_server(const char *listen_addr,
		const char *port,
		uint8_t protocol,
		uint8_t security_level,
		passport_t *passport,
		void (*on_connect)(netc_t *),
		void (*on_disconnect)(netc_t *),
		void (*on_input)(netc_t *),
		void (*on_secure)(netc_t *))
{
	int ret;
	netc_t *netc = NULL;

	netc = net_connection_new(security_level);
	if (netc == NULL) {
		jlog(L_NOTICE, "net]> server initialization failed :: %s:%i", __FILE__, __LINE__);
		return -1;
	}

	netc->on_secure = on_secure;
	netc->on_connect = on_connect;
	netc->on_disconnect = on_disconnect;
	netc->on_input = on_input;
	netc->conn_type = NET_SERVER;
	netc->protocol = protocol;
	netc->security_level = security_level;
	netc->conn_type = NET_SERVER;

	if (security_level > NET_UNSECURE)
		krypt_add_passport(netc->kconn, passport);

	switch (protocol) {
		case NET_PROTO_TCP:
			ret = netbus_tcp_server(listen_addr,
				atoi(port), net_on_connect,
				net_on_disconnect, net_on_input, netc);
			break;

		case NET_PROTO_UDT:
			ret = udtbus_server(listen_addr, port,
			    net_on_connect, net_on_disconnect,
			    net_on_input, netc);
			break;

		default:
			jlog(L_NOTICE, "net]> unknown protocol specified :: %s:%i", __FILE__, __LINE__);
			net_connection_free(netc);
			return -1;
	}

	if (ret < 0) {
		jlog(L_NOTICE, "net]> server initialization failed :: %s:%i", __FILE__, __LINE__);
		net_connection_free(netc);
		return -1;
	}

	return 0;
}

// FIXME net_p2p need an update to use DNDS Message
netc_t *net_p2p(const char *listen_addr,
		const char *dest_addr,
		const char *port,
		uint8_t protocol,
		uint8_t security_level,
		uint8_t conn_type,
		void (*on_connect)(netc_t *),
		void (*on_secure)(netc_t *),
		void (*on_disconnect)(netc_t *),
		void (*on_input)(netc_t *))
{
	int ret;
	netc_t *netc = NULL;
	peer_t *peer = NULL;
	uint8_t kconn_type;

	if (protocol != NET_PROTO_UDT) {
		jlog(L_ERROR, "net]> the only protocol that support p2p is UDT");
		return NULL;
	}

	netc = net_connection_new(security_level);
	if (netc == NULL) {
		jlog(L_ERROR, "net]> unable to initialize connection :: %s:%i", __FILE__, __LINE__);
		return NULL;
	}

	netc->on_connect = on_connect;
	netc->on_disconnect = on_disconnect;
	netc->on_input = on_input;
	netc->conn_type = conn_type;
	netc->protocol = protocol;
	netc->security_level = security_level;

	jlog(L_NOTICE, "listen_addr: %s\n", listen_addr);
	jlog(L_NOTICE, "dest_addr: %s\n", dest_addr);
	jlog(L_NOTICE, "port: %s\n", port);

	peer = udtbus_rendezvous(listen_addr, dest_addr, port, net_on_disconnect, net_on_input, netc);
	if (peer == NULL) {
		jlog(L_ERROR, "net]> unable to initialize the p2p connection :: %s:%i", __FILE__, __LINE__);
		net_connection_free(netc);
		return NULL;

	}

	netc->peer = peer;

	if (security_level > NET_UNSECURE) {

		if (conn_type == NET_P2P_CLIENT) {
			kconn_type = KRYPT_CLIENT;
		} else {
			kconn_type = KRYPT_SERVER;
		}

		// XXX - do we need to ADH then step-up to RSA or we can go with RSA the first time?
		// bev @ 30-12-2010
		ret = krypt_secure_connection(netc->kconn, KRYPT_TLS, kconn_type, KRYPT_RSA);

		if (ret < 0) {
			jlog(L_NOTICE, "net]> securing client connection failed :: %s:%i", __FILE__, __LINE__);
			net_connection_free(netc);
			return NULL;
		}

		// XXX - still not sure about the following part
		// bev @ 30-12-2010
		krypt_do_handshake(netc->kconn, NULL, 0);
	}

	netc->on_connect(netc);

	return netc;
}
