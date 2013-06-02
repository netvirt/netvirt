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

#ifndef DAO_H
#define DAO_H

#include "dsd.h"
int dao_connect(struct dsd_cfg *dsd_cfg);

/*int dao_fetch_context_by_client_id(char *client_id,
			char **id,
			char **topology_id,
			char **description,
			char **network,
			char **netmask,
			char **serverCert,
			char **serverPrivkey,
			char **trustedCert);

int dao_fetch_context(char **id,
			char **topology_id,
			char **description,
			char **network,
			char **netmask,
			char **serverCert,
			char **serverPrivkey,
			char **trustedCert);
*/

int dao_add_context(char *client_id,
			char *description,
			char *topology_id,
			char *network,
			char *embassy_certificate,
			char *embassy_privatekey,
			char *embassy_serial,
			char *passport_certificate,
			char *passport_privatekey,
			const unsigned char *ippool,
			size_t pool_size);

int dao_add_client(char *firstname,
			char *lastname,
			char *email,
			char *company,
			char *phone,
			char *country,
			char *state_province,
			char *city,
			char *postal_code,
			char *password);

int dao_fetch_context_by_client_id_desc(char *client_id, char *description,
					void *data, int (*cb_data_handler)(void *data,
					char *id,
					char *topology_id,
					char *description,
					char *client_id,
					char *network,
					char *netmask,
					char *serverCert,
					char *serverPrivkey,
					char *trustedCert));

int dao_fetch_context_embassy(char *context_id,
			char **certificate,
			char **privatekey,
			char **serial,
			char **ippool);


int dao_update_embassy_serial(char *context_id, char *serial);

int dao_add_node(char *context_id, char *uuid, char *certificate, char *privatekey, char *provcode, char *description, char *ipaddress);

int dao_update_context_ippool(char *context_id, char *ippool, int pool_size);

int dao_fetch_client_id(char **client_id, char *email, char *password);

int dao_fetch_context_by_client_id(
	char *client_id,
	void *data,
	int (*cb_data_handler)(void *data,
		char *id,
		char *topology_id,
		char *description,
		char *client_id,
		char *network,
		char *netmask,
		char *serverCert,
		char *serverPrivkey,
		char *trustedCert));

int dao_fetch_context(void *data, void (*cb_data_handler)(void *data,
							char *id,
							char *topology_id,
							char *description,
							char *client_id,
							char *network,
							char *netmask,
							char *serverCert,
							char *serverPrivkey,
							char *trustedCert));


int dao_fetch_node_from_context_id(char *context_id, void *data, int (*cb_data_handler)(void *data,
								char *uuid,
								char *description,
								char *provcode,
								char *ipaddress));
int dao_fetch_node_from_provcode(char *provcode,
					char **certificate,
					char **private_key,
					char **trustedcert,
					char **ipAddress);
char *uuid_v4(void);
#endif
