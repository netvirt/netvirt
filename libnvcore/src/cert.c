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

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <string.h>

#include "cert.h"

char *cert_cname(X509 *cert)
{
	X509_NAME	*subj_ptr;
	char		 cn[64];

	if ((subj_ptr = X509_get_subject_name(cert)) == NULL)
		return NULL;

	if (X509_NAME_get_text_by_NID(subj_ptr, NID_commonName, cn, 64) == -1)
		return NULL;

	return strdup(cn);
}

char *cert_altname_uri(X509 *cert)
{
	GENERAL_NAMES *alt;
	GENERAL_NAME *gname;
	int count, i;
	char *str = NULL;

	alt = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	count = sk_GENERAL_NAME_num(alt);
	for (i = 0; i < count; i++) {
		gname = sk_GENERAL_NAME_value(alt, i);
		if (gname->type == GEN_URI) {
			str = (char *)ASN1_STRING_data(gname->d.uniformResourceIdentifier);
			str = strdup(str);
			break;
		}
	}
	sk_GENERAL_NAME_pop_free(alt, GENERAL_NAME_free);
	return str;
}

void node_info_destroy(node_info_t *node_info)
{
	free(node_info);
}

node_info_t *altname2node_info(char *altn)
{
	// XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX@XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

	node_info_t *ninfo = NULL;

	ninfo = calloc(1, sizeof(node_info_t));

	strncpy(ninfo->type, "nva", 3);
	ninfo->type[3] = '\0';

	strncpy(ninfo->uuid, altn, 36);
	ninfo->uuid[36] = '\0';

	strncpy(ninfo->network_uuid, altn+37, 36);
	ninfo->uuid[36] = '\0';

	ninfo->v = 2;

	return ninfo;
}

node_info_t *cn2node_info(char *cn)
{
	node_info_t *ninfo = NULL;
	int len;

	if (cn == NULL) {
		return NULL;
	}

	if (!strncmp(cn, "nva-", 4) || !strncmp(cn, "dnc-", 4)) {

		// nva-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX@99999

		ninfo = calloc(1, sizeof(node_info_t));

		strncpy(ninfo->type, cn, 3);
		ninfo->type[3] = '\0';

		strncpy(ninfo->uuid, cn+4, 36);
		ninfo->uuid[36] = '\0';

		len = strlen(cn) - 41;
		if (len > 5)
			len = 5;
		strncpy(ninfo->network_id, cn+41, len);
		ninfo->network_id[5] = '\0';

		ninfo->v = 1;

		return ninfo;

	} else if (!strncmp(cn, "nva2-", 5)) {

		ninfo = calloc(1, sizeof(node_info_t));

		strncpy(ninfo->type, cn, 3);
		ninfo->type[3] = '\0';

		strncpy(ninfo->network_uuid, cn+5, 36);
		ninfo->uuid[36] = '\0';

		ninfo->v = 2;

		return ninfo;
	}

	return NULL;
}

void pki_passport_destroy(passport_t *passport)
{
	EVP_PKEY_free(passport->keyring);
	X509_free(passport->certificate);
	X509_free(passport->cacert);
	X509_STORE_free(passport->cacert_store);
	free(passport);
}

passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority)
{
	BIO *bio_memory = NULL;
	passport_t *passport;

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
	passport->cacert = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);
	passport->cacert_store = X509_STORE_new();
	X509_STORE_add_cert(passport->cacert_store, passport->cacert);

	return passport;
}

passport_t *pki_passport_load_from_file(const char *certificate_filename,
					const char *privatekey_filename,
					const char *trusted_authority_filename)
{
	BIO *bio_file = NULL;
	passport_t *passport = NULL;

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
	passport->cacert = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);
	passport->cacert_store = X509_STORE_new();
	X509_STORE_add_cert(passport->cacert_store, passport->cacert);
	BIO_free(bio_file);

	return passport;
}
