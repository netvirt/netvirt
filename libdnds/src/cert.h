/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#ifndef DNDS_CERT_H
#define DNDS_CERT_H

#include <openssl/x509_vfy.h>

typedef struct passport {

        X509 *certificate;
        EVP_PKEY *keyring;
        X509_STORE *trusted_authority;
} passport_t;

void cn2uuid(char *cn, char **uuid, char *context_id);
passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority);
passport_t *pki_passport_load_from_file(const char *certificate_filename,
                                        const char *privatekey_filename,
                                        const char *trusted_authority_filename);
#endif /* DNDS_CERT_H */
