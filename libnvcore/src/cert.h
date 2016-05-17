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

#ifndef CERT_H
#define CERT_H

#include <openssl/x509_vfy.h>

typedef struct node_info {
	char type[3+1];
	char uuid[36+1];
	char network_uuid[36+1];
	char network_id[5+1];
	char v;
} node_info_t;

typedef struct passport {
	X509 *certificate;
	EVP_PKEY *keyring;
	X509_STORE *cacert_store;
	X509 *cacert;
} passport_t;

char *cert_cname(X509 *);
char *cert_altname_uri(X509 *);
char *cert_uri(X509 *);
void node_info_destroy(node_info_t *node_info);
node_info_t *altname2node_info(char *altn);
node_info_t *cn2node_info(char *cn);
void pki_passport_destroy(passport_t *passport);
passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority);
passport_t *pki_passport_load_from_file(const char *certificate_filename,
                                        const char *privatekey_filename,
                                        const char *trusted_authority_filename);
#endif /* CERT_H */
