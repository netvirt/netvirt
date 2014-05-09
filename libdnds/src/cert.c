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


#include <openssl/bio.h>
#include <openssl/pem.h>

#include <string.h>

#include "cert.h"

passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority)
{
	BIO *bio_memory = NULL;
	passport_t *passport;
	X509 *trusted_authority_certificate;

	// create an empty passport
	passport = calloc(1, sizeof(passport_t));

	// fetch the certificate in PEM format and convert to X509
	bio_memory = BIO_new_mem_buf(certificate, strlen(certificate));
	passport->certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	// fetch the private key in PEM format and convert to EVP
	bio_memory = BIO_new_mem_buf(privatekey, strlen(privatekey));
	passport->keyring = PEM_read_bio_PrivateKey(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	// fetch the certificate authority in PEM format convert to X509
	// and add to the trusted store
	bio_memory = BIO_new_mem_buf(trusted_authority, strlen(trusted_authority));
	trusted_authority_certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	passport->trusted_authority = X509_STORE_new();
	X509_STORE_add_cert(passport->trusted_authority, trusted_authority_certificate);

	return passport;
}

passport_t *pki_passport_load_from_file(const char *certificate_filename,
					const char *privatekey_filename,
					const char *trusted_authority_filename)
{
	BIO *bio_file = NULL;
	passport_t *passport = NULL;
	X509 *trusted_authority_certificate;

	if (!certificate_filename || !privatekey_filename || !trusted_authority_filename) {
		return NULL;
	}

	// create an empty passport
	passport = calloc(1, sizeof(passport_t));

	// fetch the certificate in PEM format and convert to X509
	bio_file = BIO_new_file(certificate_filename, "r");
	if (bio_file == NULL) {
		free(passport);
		return NULL;
	}
	passport->certificate = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);
	BIO_free(bio_file);

	// fetch the private key in PEM format and convert to EVP
	bio_file = BIO_new_file(privatekey_filename, "r");
		if (bio_file == NULL) {
		free(passport);
		return NULL;
	}
	passport->keyring = PEM_read_bio_PrivateKey(bio_file, NULL, NULL, NULL);
	BIO_free(bio_file);

	// fetch the certificate authority in PEM format convert to X509
	// and add to the trusted store
	bio_file = BIO_new_file(trusted_authority_filename, "r");
	if (bio_file == NULL) {
		free(passport);
		return NULL;
	}
	trusted_authority_certificate = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);
	passport->trusted_authority = X509_STORE_new();
	X509_STORE_add_cert(passport->trusted_authority, trusted_authority_certificate);
	BIO_free(bio_file);

	return passport;
}


