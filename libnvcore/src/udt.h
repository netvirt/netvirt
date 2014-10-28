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

#ifndef UDTBUS_H
#define UDTBUS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct peer {

	int type;
	int socket;

	char *host;
	uint16_t host_len;
	uint16_t port;

	void (*on_connect)(struct peer *);
	void (*on_disconnect)(struct peer *);
	void (*on_input)(struct peer *);

	int (*ping)();
	int (*send)(struct peer *, void *, int);
	int (*recv)(struct peer *);
	void (*disconnect)(struct peer *);

	void *buffer;
	int32_t buffer_data_len;
	size_t buffer_offset;
	void *ext_ptr;

} peer_t;

struct p2p_args {

	char *listen_addr;
	char *dest_addr;
	char *local_addr;
	char *port[3];
	void (*on_connect)(struct peer *);
	void (*on_disconnect)(struct peer *);
	void (*on_input)(struct peer *);
	void *ext_ptr;
};

peer_t *udtbus_server(const char *listen_addr,
                  const char *port,
                  void (*on_connect)(peer_t *),
                  void (*on_disconnect)(peer_t *),
                  void (*on_input)(peer_t *),
                  void *ext_ptr);

void *udtbus_rendezvous(void *args);

peer_t *udtbus_client(const char *listen_addr,
                      const char *port,
                      void (*on_disconnect)(peer_t *),
                      void (*on_input)(peer_t *));
void udtbus_poke_queue();
int udtbus_init();
void udtbus_fini();

#ifdef __cplusplus
}
#endif

#endif
