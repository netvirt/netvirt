/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
 * Nicolas J. Bouliane <nib@m4nt.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef NVAGENT_H
#define NVAGENT_H

#include <sys/tree.h>

#include <event2/event.h>

#include <tapcfg.h>

#include <pki.h>

#ifdef __cplusplus
extern "C" {
#endif

struct network {
	RB_ENTRY(network)	 entry;
	size_t			 idx;
	char			*name;
	char			*ctlsrv_addr;
	char			*cert;
	char			*pvkey;
	char			*cacert;
};

void	switch_fini(void);
int	switch_init(tapcfg_t *, int, const char *, const char *, const char *);

int	ndb_init(void);
void	ndb_networks(void);
struct network *ndb_network(const char *);
int	ndb_provisioning(const char *, const char *);

int	control_init(const char *);
void	control_fini(void);

extern struct event_base 	*ev_base;

#ifdef __cplusplus
}
#endif

#endif
