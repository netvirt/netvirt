/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
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

#ifndef DNDS_TCPBUS_H
#define DNDS_TCPBUS_H

peer_t *tcpbus_server(const char *in_addr,
		   const char *port,
		   void (*on_connect)(peer_t*),
		   void (*on_disconnect)(peer_t*),
		   void (*on_input)(peer_t*),
		   void *ext_ptr);

peer_t *tcpbus_client(const char *addr,
			  const char *port,
			  void (*on_disconnect)(peer_t*),
			  void (*on_input)(peer_t*));


void tcpbus_init();
int tcpbus_ion_poke();

#endif
