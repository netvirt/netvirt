/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifndef DNDS_PKI_H
#define DNDS_PKI_H

#include <stdbool.h>
#include <stdint.h>

#include <openssl/ssl.h>

#include <krypt.h>

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

void pki_free_digital_id(digital_id_t *digital_id);

void pki_embassy_free(embassy_t *embassy);
embassy_t *pki_embassy_new(digital_id_t *digital_id, uint32_t expiration_delay);

void pki_passport_free(passport_t *passport);
passport_t *pki_embassy_deliver_passport(embassy_t *embassy, digital_id_t *digital_id, uint32_t expiration_delay);

embassy_t *pki_embassy_load_from_memory(char *certificate, char *privatekey, uint32_t serial);
passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority);
#endif
