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

#ifndef PKI_H
#define PKI_H

#include <stdbool.h>
#include <stdint.h>

#include <openssl/ssl.h>

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


typedef struct digital_id {

	char *commonName;
	char *altName;
	char *stateOrProvinceName;
	char *localityName;
	char *emailAddress;
	char *organizationName;
} digital_id_t;

typedef struct embassy {

	X509 *certificate;
	EVP_PKEY *keyring;
	uint32_t serial;
} embassy_t;

EVP_PKEY *pki_generate_keyring();
X509_REQ *pki_certificate_request(EVP_PKEY *keyring, digital_id_t *digital_id);
void pki_write_certreq_in_mem(X509_REQ *certreq, char **certreq_ptr, long *size);

void pki_init();
uint32_t pki_expiration_delay(uint8_t years);
digital_id_t *pki_digital_id(char *commonName,
				char *countryName,
				char *stateOrProvinceName,
				char *localityName,
				char *emailAddress,
				char *organizationName);


void pki_write_certificate_in_mem(X509 *certificate, char **certificate_ptr, long *size);
void pki_write_privatekey_in_mem(EVP_PKEY *privatekey, char **privatekey_ptr, long *size);

char *pki_gen_key();
char *pki_gen_uid();

void pki_free_digital_id(digital_id_t *digital_id);

void pki_embassy_free(embassy_t *embassy);
embassy_t *pki_embassy_new(digital_id_t *digital_id, uint32_t expiration_delay);

void pki_passport_free(passport_t *passport);
passport_t *pki_embassy_deliver_passport(embassy_t *embassy, digital_id_t *digital_id, uint32_t expiration_delay);

embassy_t *pki_embassy_load_from_memory(char *certificate, char *privatekey, uint32_t serial);
int pki_bootstrap_certs();
#endif
