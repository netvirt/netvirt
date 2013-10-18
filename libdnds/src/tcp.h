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

#ifndef DNDS_TCPBUS_H
#define DNDS_TCPBUS_H

int tcpbus_server(const char *in_addr,
		   char *port,
		   void (*on_connect)(peer_t*),
		   void (*on_disconnect)(peer_t*),
		   void (*on_input)(peer_t*),
		   void *ext_ptr);

peer_t *tcpbus_client(const char *addr,
			  const char *port,
			  void (*on_disconnect)(peer_t*),
			  void (*on_input)(peer_t*));


#endif
