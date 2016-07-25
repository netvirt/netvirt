/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <err.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include "switch.h"

void
accept_cb(struct evconnlistener *listener, int fd,
    struct sockaddr *address, int socklen,
    void *arg)
{

}

DH *
get_dh_1024() {

	DH *dh = NULL;
	static unsigned char dh1024_p[]={
		0xDE,0xD3,0x80,0xD7,0xE1,0x8E,0x1B,0x5D,0x5C,0x76,0x61,0x79,
		0xCA,0x8E,0xCD,0xAD,0x83,0x49,0x9E,0x0B,0xC0,0x2E,0x67,0x33,
	        0x5F,0x58,0x30,0x9C,0x13,0xE2,0x56,0x54,0x1F,0x65,0x16,0x27,
	        0xD6,0xF0,0xFD,0x0C,0x62,0xC4,0x4F,0x5E,0xF8,0x76,0x93,0x02,
	        0xA3,0x4F,0xDC,0x2F,0x90,0x5D,0x77,0x7E,0xC6,0x22,0xD5,0x60,
	        0x48,0xF5,0xFB,0x5D,0x46,0x5D,0xF5,0x97,0x20,0x35,0xA6,0xEE,
	        0xC0,0xA0,0x89,0xEE,0xAB,0x22,0x68,0x96,0x8B,0x64,0x69,0xC7,
	        0xEB,0x41,0xDF,0x74,0xDF,0x80,0x76,0xCF,0x9B,0x50,0x2F,0x08,
	        0x13,0x16,0x0D,0x2E,0x94,0x0F,0xEE,0x29,0xAC,0x92,0x7F,0xA6,
	        0x62,0x49,0x41,0x0F,0x54,0x39,0xAD,0x91,0x9A,0x23,0x31,0x7B,
	        0xB3,0xC9,0x34,0x13,0xF8,0x36,0x77,0xF3,
	};

	static unsigned char dh1024_g[]={
		0x02,
	};

	dh = DH_new();
	if (dh == NULL) {
		return NULL;
	}

	dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
	dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

	if (dh->p == NULL || dh->g == NULL) {
		DH_free(dh);
		return NULL;
	}

	return dh;
}

void
switch_init(json_t *config)
{
	SSL				*ssl;
	SSL_CTX				*ctx;
	extern struct event_base	*ev_base;
	struct evconnlistener		*listener;
	struct addrinfo			*ai, hints;
	const char			*ip;
	const char			*port;
	int				 status;

	if (json_unpack(config, "{s:s}", "switch_ip", &ip) < 0)
		errx(1, "switch_ip is not present in config");

	if (json_unpack(config, "{s:s}", "switch_port", &port) < 0)
		errx(1, "switch_port is not present in config");

	SSL_load_error_strings();
	SSL_library_init();

	if (!RAND_poll())
		err(1, "RAND_poll");

	if ((ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL)
		err(1, "SSL_CTX_NEW");

	SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
	SSL_CTX_set_verify(ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	if ((ssl = SSL_new(ctx)) == NULL)
		err(1, "SSL_new");

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		errx(1, "getaddrinfo: %s", gai_strerror(status));

	if ((listener = evconnlistener_new_bind(ev_base, accept_cb, ctx,
	    LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
	    ai->ai_addr, (int)ai->ai_addrlen)) == NULL)
		err(1, "evconnlistener_new_bind");
	
	SSL_CTX_free(ctx);	
	freeaddrinfo(ai);
}

void
switch_fini()
{

}
