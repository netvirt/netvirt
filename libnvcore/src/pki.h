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

#ifndef PKI_H
#define PKI_H

#include <stdbool.h>
#include <stdint.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>

typedef struct node_info {
	char type[3+1];
	char uuid[36+1];
	char context_id[5+1];
} node_info_t;

typedef struct digital_id {

	char *commonName;
	char *countryName;
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

typedef struct passport {

        X509 *certificate;
        EVP_PKEY *keyring;
        X509_STORE *trusted_authority;
} passport_t;

void pki_init();


EVP_PKEY *pki_generate_keyring();
X509_REQ *pki_certificate_request(EVP_PKEY *keyring, digital_id_t *digital_id);

void pki_passport_destroy(passport_t *passport);

uint32_t pki_expiration_delay(uint8_t years);

digital_id_t *pki_digital_id(char *commonName,
				char *countryName,
				char *stateOrProvinceName,
				char *localityName,
				char *emailAddress,
				char *organizationName);


void pki_write_certificate_in_mem(X509 *certificate, char **certificate_ptr, long *size);
void pki_write_privatekey_in_mem(EVP_PKEY *privatekey, char **privatekey_ptr, long *size);

int pki_write_certificate(X509 *certificate, const char *filename);
int pki_write_privatekey(EVP_PKEY *privatekey, const char *filename);

void pki_free_digital_id(digital_id_t *digital_id);

void pki_embassy_free(embassy_t *embassy);
embassy_t *pki_embassy_new(digital_id_t *digital_id, uint32_t expiration_delay);

void pki_passport_free(passport_t *passport);
passport_t *pki_embassy_deliver_passport(embassy_t *embassy, digital_id_t *digital_id, uint32_t expiration_delay);

embassy_t *pki_embassy_load_from_memory(char *certificate, char *privatekey, uint32_t serial);

passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority);

passport_t *pki_passport_load_from_file(const char *certificate_filename,
                                        const char *privatekey_filename,
                                        const char *trusted_authority_filename);
#endif
