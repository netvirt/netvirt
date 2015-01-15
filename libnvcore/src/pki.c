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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "logger.h"
#include "pki.h"

// openssl x509 -in ./certificate.pem -text

/* TODO handle errors
 * 	use EVP_sha256
 * 	add a function to write in a file/binary blob the signing request
 */

void
node_info_destroy(node_info_t *node_info)
{
	free(node_info);
}

node_info_t *
cn2node_info(char *cn)
{
	/* expected: dnc-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX@99999 */
	node_info_t *ninfo = NULL;

	if (cn == NULL || strlen(cn) < 42)
		return NULL;

	ninfo = calloc(1, sizeof(node_info_t));

	strncpy(ninfo->type, cn, 3);
        ninfo->type[3] = '\0';

        strncpy(ninfo->uuid, cn+4, 36);
        ninfo->uuid[36] = '\0';

        strncpy(ninfo->context_id, cn+41, 5);
        ninfo->context_id[5] = '\0';

	return ninfo;
}

EVP_PKEY *
pki_generate_keyring()
{
	jlog(L_DEBUG, "pki_generate_keyring");

	EVP_PKEY *keyring;
	RSA *rsa_keys;

	/* create a new keyring */
	keyring = EVP_PKEY_new();

	/* generate RSA-type public and private keys */
	rsa_keys = RSA_generate_key(4096, RSA_F4, NULL, NULL);

	/* if the keys are not usable, give it another try */
	if (RSA_check_key(rsa_keys) != 1) {

		RSA_free(rsa_keys);
		rsa_keys = RSA_generate_key(4096, RSA_F4, NULL, NULL);

		/* we are in serious problem here */
		if (RSA_check_key(rsa_keys) != 1) {
			RSA_free(rsa_keys);
			return NULL;
		}
	}

	/* add the RSA keys into the keyring */
	EVP_PKEY_set1_RSA(keyring, rsa_keys);
	RSA_free(rsa_keys);

	return keyring;
}

X509_REQ *
pki_certificate_request(EVP_PKEY *keyring, digital_id_t *digital_id)
{
	jlog(L_DEBUG, "pki_certificate_request");

	X509_REQ *cert_req;
	X509_NAME *subject;

	/* create a certificate signing request */
	cert_req = X509_REQ_new();

	/* set public key to the CSR */
	X509_REQ_set_pubkey(cert_req, keyring);

	/* set certificate request 'Subject:' */
	subject = X509_NAME_new();

	X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, (unsigned char*)digital_id->commonName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "countryName", MBSTRING_ASC, (unsigned char*)digital_id->countryName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "stateOrProvinceName", MBSTRING_ASC, (unsigned char*)digital_id->stateOrProvinceName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "localityName", MBSTRING_ASC, (unsigned char*)digital_id->localityName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "emailAddress", MBSTRING_ASC, (unsigned char*)digital_id->emailAddress, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "organizationName", MBSTRING_ASC, (unsigned char*)digital_id->organizationName, -1, -1, 0);

	X509_REQ_set_subject_name(cert_req, subject);
	X509_NAME_free(subject);

	/* sign the CSR with our keys */
	X509_REQ_sign(cert_req, keyring, EVP_sha256());

	return cert_req;
}

static X509 *
pki_certificate(X509_NAME *issuer, X509_REQ *cert_req,
		uint8_t is_cert_authority, uint32_t serial, uint32_t expiration_delay)
{
	jlog(L_DEBUG, "pki_certificate");

	EVP_PKEY *pub_key = NULL;
	X509 *certificate = NULL;
	X509_NAME *subject = NULL;

	X509V3_CTX ctx;
	X509_EXTENSION *ext = NULL;

	/* Verify CSR signature */
	pub_key = X509_REQ_get_pubkey(cert_req);
	if (pub_key == NULL) {
		jlog(L_WARNING, "no signature present in the certificate signing request");
		return NULL;
	}

	if (X509_REQ_verify(cert_req, pub_key) != 1) {
		jlog(L_WARNING, "the certificate signing request signature is invalid");
		return NULL;
	}

	/* create a new certificate */
	certificate = X509_new();

	/* set certificate unique serial number */
	ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial);

	/* set certificate 'Subject:' */
	subject = X509_REQ_get_subject_name(cert_req);
	X509_set_subject_name(certificate, subject);

	/* set certificate 'Issuer:' */
	X509_set_issuer_name(certificate, issuer);

	/* set X509v3 extension "basicConstraints" CA:TRUE/FALSE */
	X509V3_set_ctx(&ctx, NULL, certificate, cert_req, NULL, 0);

	if (is_cert_authority == true)
		ext = X509V3_EXT_conf(NULL, &ctx, "basicConstraints", "CA:TRUE");
	else
		ext = X509V3_EXT_conf(NULL, &ctx, "basicConstraints", "CA:FALSE");

	X509_add_ext(certificate, ext, -1);
	X509_EXTENSION_free(ext);

	/* set certificate version 3 == 0x2 */
	X509_set_version(certificate, 0x2);

	/* set the 'notBefore' to yersterday */
	X509_gmtime_adj(X509_get_notBefore(certificate), -(24*60*60));
	/* set certificate expiration delay */

	X509_gmtime_adj(X509_get_notAfter(certificate), expiration_delay);

	return certificate;
}

static void
pki_sign_certificate(EVP_PKEY *keyring, X509 *certificate)
{
	jlog(L_NOTICE, "pki_sign_certificate");

	X509_sign(certificate, keyring, EVP_sha256());
}

void
pki_free_digital_id(digital_id_t *digital_id)
{
	free(digital_id->commonName);
	free(digital_id->countryName);
	free(digital_id->stateOrProvinceName);
	free(digital_id->localityName);
	free(digital_id->emailAddress);
	free(digital_id->organizationName);

	free(digital_id);
}

digital_id_t *
pki_digital_id(char *commonName,
		char *countryName,
		char *stateOrProvinceName,
		char *localityName,
		char *emailAddress,
		char *organizationName)
{
	jlog(L_DEBUG, "pki_digital_id");

	digital_id_t *digital_id;
	digital_id = calloc(1, sizeof(digital_id_t));

	digital_id->commonName = strdup(commonName);
	digital_id->countryName = strdup(countryName);
	digital_id->localityName = strdup(localityName);
	digital_id->stateOrProvinceName = strdup(stateOrProvinceName);
	digital_id->emailAddress = strdup(emailAddress);
	digital_id->organizationName = strdup(organizationName);

	return digital_id;
}

void
pki_embassy_free(embassy_t *embassy)
{
	X509_free(embassy->certificate);
	EVP_PKEY_free(embassy->keyring);
	free(embassy);
}

embassy_t *
pki_embassy_new(digital_id_t *digital_id, uint32_t expiration_delay)
{
	jlog(L_NOTICE, "pki_embassy_new");

	embassy_t *embassy;
	embassy = calloc(1, sizeof(embassy_t));

	EVP_PKEY *keyring;
	X509_REQ *cert_req;
	X509 *certificate;
	X509_NAME *issuer;
	uint32_t serial = 0;

	/* generate RSA public and private keys */
	keyring = pki_generate_keyring();

	/* create a certificate signing request */
	cert_req = pki_certificate_request(keyring, digital_id);

	/* fetch the 'Subject:' name from the certificate request
	 * note that this is a self-signed certificate therefore
	 * the 'Subject:' and 'Issuer:' are the same */
	issuer = X509_REQ_get_subject_name(cert_req);

	/* create the certificate from the certificate request and keyring */
	certificate = pki_certificate(issuer, cert_req, true, serial++, expiration_delay);

	/* self-sign the certificate with our own keyring */
	pki_sign_certificate(keyring, certificate);

	/* create the new embassy */
	embassy->certificate = certificate;
	embassy->keyring = keyring;
	embassy->serial = serial;

	return embassy;
}

void
pki_passport_free(passport_t *passport)
{
	X509_free(passport->certificate);
	EVP_PKEY_free(passport->keyring);
	X509_STORE_free(passport->trusted_authority);

	free(passport);
}

passport_t *
pki_embassy_deliver_passport(embassy_t *embassy, digital_id_t *digital_id, uint32_t expiration_delay)
{
	jlog(L_NOTICE, "pki_embassy_deliver_passport");

	passport_t *passport;
	passport = calloc(1, sizeof(passport_t));

	EVP_PKEY *keyring;
	X509_REQ *cert_req;
	X509 *certificate;
	X509_NAME *issuer;

	/* generate RSA public and private keys */
	keyring = pki_generate_keyring();

	/* create a certificate signing request */
	cert_req = pki_certificate_request(keyring, digital_id);

	/* fetch the 'Subject:' name from the certificate authority */
	issuer = X509_get_subject_name(embassy->certificate);

	/* create the certificate from the certificate request and keyring */
	certificate = pki_certificate(issuer, cert_req, false, embassy->serial++, expiration_delay);

	/* sign the certificate with the certificate authority */
	pki_sign_certificate(embassy->keyring, certificate);

	/* create the new passport */
	passport->certificate = certificate;
	passport->keyring = keyring;
	passport->trusted_authority = X509_STORE_new();

	/* add the trusted certificate authority */
	X509_STORE_add_cert(passport->trusted_authority, embassy->certificate);

	/* deliver the passport */
	return passport;
}

uint32_t
pki_expiration_delay(uint8_t years)
{
	/* if years > 68, it will overflow the certificate 'Not After Date'
	 * dont be silly, we will never need more than 68 years ! */
	if (years > 68)
		years = 68;

	return years*365*24*60*60;
}

embassy_t *
pki_embassy_load_from_memory(char *certificate, char *privatekey, uint32_t serial)
{
	BIO *bio_memory = NULL;
	embassy_t *embassy;

	/* create an empty embassy */
	embassy = calloc(1, sizeof(embassy_t));

	/* fetch the certificate in PEM format and convert to X509 */
	bio_memory = BIO_new_mem_buf(certificate, strlen(certificate));
	embassy->certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	/* fetch the private key in PEM format and convert to EVP */
	bio_memory = BIO_new_mem_buf(privatekey, strlen(privatekey));
	embassy->keyring = PEM_read_bio_PrivateKey(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	embassy->serial = serial;

	return embassy;
}

passport_t *
pki_passport_load_from_file(const char *certificate_filename,
			const char *privatekey_filename,
			const char *trusted_authority_filename)
{
	BIO *bio_file = NULL;
	passport_t *passport = NULL;
	X509 *trusted_authority_certificate;

	if (!certificate_filename || !privatekey_filename || !trusted_authority_filename) {
		return NULL;
	}

	/* create an empty passport */
	passport = calloc(1, sizeof(passport_t));

	/* fetch the certificate in PEM format and convert to X509 */
	bio_file = BIO_new_file(certificate_filename, "r");
	if (bio_file == NULL) {
		free(passport);
		return NULL;
	}
	passport->certificate = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);
	BIO_free(bio_file);

	/* fetch the private key in PEM format and convert to EVP */
	bio_file = BIO_new_file(privatekey_filename, "r");
		if (bio_file == NULL) {
		free(passport);
		return NULL;
	}
	passport->keyring = PEM_read_bio_PrivateKey(bio_file, NULL, NULL, NULL);
	BIO_free(bio_file);

	/* fetch the certificate authority in PEM format convert to X509
	 * and add to the trusted store */
	bio_file = BIO_new_file(trusted_authority_filename, "r");
	if (bio_file == NULL) {
		free(passport);
		return NULL;
	}
	trusted_authority_certificate = PEM_read_bio_X509(bio_file, NULL, NULL, NULL);
	passport->trusted_authority = X509_STORE_new();
	X509_STORE_add_cert(passport->trusted_authority, trusted_authority_certificate);
	X509_free(trusted_authority_certificate);
	BIO_free(bio_file);

	return passport;
}

passport_t *
pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority)
{
	BIO *bio_memory = NULL;
	passport_t *passport;
	X509 *trusted_authority_certificate;

	/* create an empty passport */
	passport = calloc(1, sizeof(passport_t));

	/* fetch the certificate in PEM format and convert to X509 */
	bio_memory = BIO_new_mem_buf(certificate, strlen(certificate));
	passport->certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	/* fetch the private key in PEM format and convert to EVP */
	bio_memory = BIO_new_mem_buf(privatekey, strlen(privatekey));
	passport->keyring = PEM_read_bio_PrivateKey(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	/* fetch the certificate authority in PEM format convert to X509
	 * and add to the trusted store */
	bio_memory = BIO_new_mem_buf(trusted_authority, strlen(trusted_authority));
	trusted_authority_certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);
	passport->trusted_authority = X509_STORE_new();
	X509_STORE_add_cert(passport->trusted_authority, trusted_authority_certificate);
	X509_free(trusted_authority_certificate);

	return passport;
}

void
pki_write_certreq_in_mem(X509_REQ *certreq, char **certreq_ptr, long *size)
{
	BIO *bio_mem = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio_mem, certreq);

	*size = BIO_get_mem_data(bio_mem, certreq_ptr);
	*(*certreq_ptr + *size) = '\0';

	(void)BIO_set_close(bio_mem, BIO_NOCLOSE);
	BIO_free(bio_mem);
}

void
pki_write_certificate_in_mem(X509 *certificate, char **certificate_ptr, long *size)
{
	BIO *bio_mem = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio_mem, certificate);

	*size = BIO_get_mem_data(bio_mem, certificate_ptr);
	*(*certificate_ptr + *size) = '\0';

	(void)BIO_set_close(bio_mem, BIO_NOCLOSE);
	BIO_free(bio_mem);
}

void
pki_write_privatekey_in_mem(EVP_PKEY *privatekey, char **privatekey_ptr, long *size)
{
	BIO *bio_mem = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio_mem, privatekey, NULL, NULL, 0, 0, NULL);

	*size = BIO_get_mem_data(bio_mem, privatekey_ptr);
	*(*privatekey_ptr + *size) = '\0';

	(void)BIO_set_close(bio_mem, BIO_NOCLOSE);
	BIO_free(bio_mem);
}

int
pki_write_certificate(X509 *certificate, const char *filename)
{
	int ret = 0;
	BIO *bio_file = NULL;

	bio_file = BIO_new_file(filename, "w");
	if (bio_file == NULL) {
		ret = -1;
		goto out;
	}
	ret = PEM_write_bio_X509(bio_file, certificate);
	if (ret != 1) {
		ret = -1;
	}
	BIO_free(bio_file);
out:
	return ret;
}

int
pki_write_privatekey(EVP_PKEY *privatekey, const char *filename)
{
	int ret = 0;
	BIO *bio_file = NULL;

	bio_file = BIO_new_file(filename, "w");
	if (bio_file == NULL) {
		ret = -1;
		goto out;
	}
	ret = PEM_write_bio_PrivateKey(bio_file, privatekey, NULL, NULL, 0, 0, NULL);
	if (ret != 1) {
		ret = -1;
		goto out;
	}
	BIO_free(bio_file);
out:
	return ret;
}

void
pki_passport_destroy(passport_t *passport)
{
	EVP_PKEY_free(passport->keyring);
	X509_free(passport->certificate);
	X509_STORE_free(passport->trusted_authority);
	free(passport);
}

void
pki_init()
{
	/* SSL_library_init(); */
	/* SSL_load_error_strings(); */
}

