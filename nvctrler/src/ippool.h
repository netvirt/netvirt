/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
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

#ifndef IPPOOL_H
#define IPPOOL_H

#include <netinet/in.h>

struct ippool {

	uint32_t hosts;			/* Maximum possible host. */

	struct in_addr hostmin;		/* First host address. */
	struct in_addr hostmax;		/* Last host address. */
	struct in_addr address;		/* Network address. */
	struct in_addr netmask;		/* Network address mask. */

	unsigned char *pool;		/* Bitmap holding used address. */
};

char *ippool_get_ip(struct ippool *);
void ippool_release_ip(struct ippool *, char *);
struct ippool *ippool_new(char *, char *);
void ippool_free(struct ippool *ippool);

#endif
