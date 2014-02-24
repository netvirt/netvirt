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

#ifndef IPPOOL_H
#define IPPOOL_H

#include <netinet/in.h>

typedef struct ippool {

	uint32_t hosts;

	struct in_addr hostmin;
	struct in_addr hostmax;

	struct in_addr address;
	struct in_addr netmask;

	unsigned char *pool;

} ippool_t;

extern char *ippool_get_ip(ippool_t *);
extern void ippool_release_ip(ippool_t *, char *);
extern ippool_t *ippool_new(char *, char *);
extern void ipcalc(ippool_t *ippool, char *address, char *netmask);

#endif
