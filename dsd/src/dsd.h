// Directory Service Daemon
// Copyright (C) Nicolas Bouliane, Mind4Networks, 2010

#ifndef DNDS_DSD_H
#define DNDS_DSD_H

#include <dnds/net.h>

#define SESS_AUTH	0x1
#define SESS_NOT_AUTH	0x2

typedef struct {

	uint8_t auth;
	netc_t *netc;
	uint32_t timeout_id;

} ds_sess_t; // Directory Service session information

extern int dsd_init(char *liste_addr, char *port, char *certificate, char *privatekey, char *trusted_authority);

#endif // DNDS_DSD_H
