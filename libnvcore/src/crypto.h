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

#ifndef KRYPT_H
#define KRYPT_H

#include <stdint.h>
#include <openssl/ssl.h>

#include "pki.h"

#define KRYPT_TLS	0x1	// Transport Layer Security { NET_TCP, NET_UDT }
#define KRYPT_DTLS	0x2	// Datagram Transport Layer Security { unused }

#define KRYPT_CLIENT	0x1	// Connection type Client
#define KRYPT_SERVER	0x2	// Connection type Server

#define KRYPT_NOINIT	0x1	// Connection status Not Initialized
#define KRYPT_HANDSHAKE 0x2	// Connection status Handshaking
#define KRYPT_SECURE	0x4	// Conecction status Secure
#define KRYPT_FAIL	0x8	// Connection status Fail, something went wrong during the handshake

typedef struct krypt {

	SSL *ssl;			// SSL Connection
	SSL_CTX *ctx;			// SSL Context

	STACK_OF(X509_NAME) *cert_name;	// Certificate CommonName

	BIO *internal_bio;		// used to bridge Network and SSL non-blocking operations
	BIO *network_bio;		// BIO is a I/O abstraction provided by openSSL

	passport_t *passport;		// Certificate and key used to negotiate RSA
	char client_cn[256];		// Client certificate commonName

	uint8_t status;			// Status { NOINIT, HANDSHAKE, SECURE, FAIL }
	uint8_t conn_type;

	uint8_t *buf_decrypt;		// Decrypted data
	size_t buf_decrypt_size;	// Buffer size in memory
	size_t buf_decrypt_data_size;	// Data size in the buffer

	uint8_t *buf_encrypt;		// Encrypted data
	size_t buf_encrypt_size;	// Buffer size in memory
	size_t buf_encrypt_data_size;	// Data size in the buffer

	passport_t *(*servername_cb)(const char *); // TLS Server Name Indication callback

} krypt_t;

void krypt_set_renegotiate(krypt_t *kconn);
int krypt_set_rsa(krypt_t *kconn);
int krypt_step_up(krypt_t *kconn);
int krypt_encrypt_buf(krypt_t *kcon, uint8_t *buf, size_t buf_data_size);
int krypt_push_encrypted_data(krypt_t *kconn, uint8_t *buf, size_t buf_data_size);
int krypt_decrypt_buf(krypt_t *kconn);
int krypt_do_handshake(krypt_t *kconn, uint8_t *buf, size_t buf_data_size);
int krypt_secure_connection(krypt_t *kconn, uint8_t state);
void krypt_add_passport(krypt_t *kconn, passport_t *passport);
void krypt_print_cipher(krypt_t *kconn);

void krypt_fini();
int krypt_init();

#endif /* KRYPT_H */
