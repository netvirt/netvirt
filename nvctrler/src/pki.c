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

/* TODO handle errors */

static EVP_PKEY *pki_generate_keyring()
{
	jlog(L_DEBUG, "pki_generate_keyring");

	EVP_PKEY *keyring;
	RSA *rsa_keys;

	// create a new keyring
	keyring = EVP_PKEY_new();

	// generate RSA type public and private keys
	rsa_keys = RSA_generate_key(2048, RSA_F4, NULL, NULL);

	// if the keys are not usable, give it another try
	if (RSA_check_key(rsa_keys) != 1) {

		RSA_free(rsa_keys);
		rsa_keys = RSA_generate_key(2048, RSA_F4, NULL, NULL);

		// we are in serious problem here
		if (RSA_check_key(rsa_keys) != 1) {
			RSA_free(rsa_keys);
			return NULL;
		}
	}

	// add the RSA keys into the keyring
	EVP_PKEY_set1_RSA(keyring, rsa_keys);
	RSA_free(rsa_keys);

	return keyring;
}

static X509_REQ *pki_certificate_request(EVP_PKEY *keyring, digital_id_t *digital_id)
{
	jlog(L_DEBUG, "pki_certificate_request");

	X509_REQ *cert_req;
	X509_NAME *subject;
	const EVP_MD *message_digest;

	// create a certificate request
	cert_req = X509_REQ_new();

	// set certificate request 'Subject:'
	subject = X509_NAME_new();

	X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, (unsigned char*)digital_id->commonName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "countryName", MBSTRING_ASC, (unsigned char*)digital_id->countryName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "stateOrProvinceName", MBSTRING_ASC, (unsigned char*)digital_id->stateOrProvinceName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "localityName", MBSTRING_ASC, (unsigned char*)digital_id->localityName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "emailAddress", MBSTRING_ASC, (unsigned char*)digital_id->emailAddress, -1, -1, 0);
	X509_NAME_add_entry_by_txt(subject, "organizationName", MBSTRING_ASC, (unsigned char*)digital_id->organizationName, -1, -1, 0);

	X509_REQ_set_subject_name(cert_req, subject);
	X509_NAME_free(subject);

	// set certificate request public key
	X509_REQ_set_pubkey(cert_req, keyring);

	// create a message digest
	message_digest = EVP_sha1();

	// sign certificate request
	X509_REQ_sign(cert_req, keyring, message_digest);

	return cert_req;
}

static X509 *pki_certificate(X509_NAME *issuer, EVP_PKEY *keyring, X509_REQ *cert_req,
				uint8_t is_cert_authority, uint32_t serial, uint32_t expiration_delay)
{
	jlog(L_DEBUG, "pki_certificate");

	X509 *certificate;
	X509_NAME *subject;

	X509V3_CTX ctx;
	X509_EXTENSION *ext;

	// create a new certificate
	certificate = X509_new();

	// set certificate unique serial number
	ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial);

	// set certificate 'Subject:'
	subject = X509_REQ_get_subject_name(cert_req);
	X509_set_subject_name(certificate, subject);

	// set certificate 'Issuer:'
	X509_set_issuer_name(certificate, issuer);

	// set X509v3 extension "basicConstraints" CA:TRUE/FALSE
	X509V3_set_ctx(&ctx, NULL, certificate, cert_req, NULL, 0);

	if (is_cert_authority == true)
		ext = X509V3_EXT_conf(NULL, &ctx, "basicConstraints", "CA:TRUE");
	else
		ext = X509V3_EXT_conf(NULL, &ctx, "basicConstraints", "CA:FALSE");

	X509_add_ext(certificate, ext, -1);
	X509_EXTENSION_free(ext);

	// set certificate version 3
	X509_set_version(certificate, 0x2);

	// set certificate public key
	X509_set_pubkey(certificate, keyring);

	// set the 'notBefore' to yersterday
	X509_gmtime_adj(X509_get_notBefore(certificate), -(24*60*60));
	// set certificate expiration delay
	X509_gmtime_adj(X509_get_notAfter(certificate), expiration_delay);

	return certificate;
}

static void pki_sign_certificate(EVP_PKEY *keyring, X509 *certificate)
{
	jlog(L_NOTICE, "pki_sign_certificate");

	X509_sign(certificate, keyring, EVP_sha1());
}

void pki_free_digital_id(digital_id_t *digital_id)
{
	free(digital_id->commonName);
	free(digital_id->countryName);
	free(digital_id->stateOrProvinceName);
	free(digital_id->localityName);
	free(digital_id->emailAddress);
	free(digital_id->organizationName);

	free(digital_id);
}

digital_id_t *pki_digital_id(char *commonName,
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

void pki_embassy_free(embassy_t *embassy)
{
	X509_free(embassy->certificate);
	EVP_PKEY_free(embassy->keyring);
	free(embassy);
}

embassy_t *pki_embassy_new(digital_id_t *digital_id, uint32_t expiration_delay)
{
	jlog(L_NOTICE, "pki_embassy_new");

	embassy_t *embassy;
	embassy = calloc(1, sizeof(embassy_t));

	EVP_PKEY *keyring;
	X509_REQ *cert_req;
	X509 *certificate;
	X509_NAME *issuer;
	uint32_t serial = 0;

	// generate RSA public and private keys
	keyring = pki_generate_keyring();

	// create a certificate signing request
	cert_req = pki_certificate_request(keyring, digital_id);

	// fetch the 'Subject:' name from the certificate request
	// note that this is a self-signed certificate therefore
	// the 'Subject:' and 'Issuer:' are the same
	issuer = X509_REQ_get_subject_name(cert_req);

	// create the certificate from the certificate request and keyring
	certificate = pki_certificate(issuer, keyring, cert_req, true, serial++, expiration_delay);

	// self-sign the certificate with our own keyring
	pki_sign_certificate(keyring, certificate);

	// create the new embassy
	embassy->certificate = certificate;
	embassy->keyring = keyring;
	embassy->serial = serial;

	return embassy;
}

void pki_passport_free(passport_t *passport)
{
	X509_free(passport->certificate);
	EVP_PKEY_free(passport->keyring);
	X509_STORE_free(passport->trusted_authority);

	free(passport);
}

passport_t *pki_embassy_deliver_passport(embassy_t *embassy, digital_id_t *digital_id, uint32_t expiration_delay)
{
	jlog(L_NOTICE, "pki_embassy_deliver_passport");

	passport_t *passport;
	passport = calloc(1, sizeof(passport_t));

	EVP_PKEY *keyring;
	X509_REQ *cert_req;
	X509 *certificate;
	X509_NAME *issuer;

	// generate RSA public and private keys
	keyring = pki_generate_keyring();

	// create a certificate signing request
	cert_req = pki_certificate_request(keyring, digital_id);

	// fetch the 'Subject:' name from the certificate authority
	issuer = X509_get_subject_name(embassy->certificate);

	// create the certificate from the certificate request and keyring
	certificate = pki_certificate(issuer, keyring, cert_req, false, embassy->serial++, expiration_delay);

	// sign the certificate with the certificate authority
	pki_sign_certificate(embassy->keyring, certificate);

	// create the new passport
	passport->certificate = certificate;
	passport->keyring = keyring;
	passport->trusted_authority = X509_STORE_new();

	// add the trusted certificate authority
	X509_STORE_add_cert(passport->trusted_authority, embassy->certificate);

	// deliver the passport
	return passport;
}

uint32_t pki_expiration_delay(uint8_t years)
{
	// if years > 68, it will overflow the certificate 'Not After Date'
	// dont be silly, we will never need more than 68 years !
	if (years > 68)
		years = 68;

	return years*365*24*60*60;
}

embassy_t *pki_embassy_load_from_memory(char *certificate, char *privatekey, uint32_t serial)
{
	BIO *bio_memory = NULL;
	embassy_t *embassy;

	// create an empty embassy
	embassy = calloc(1, sizeof(embassy_t));

	// fetch the certificate in PEM format and convert to X509
	bio_memory = BIO_new_mem_buf(certificate, strlen(certificate));
	embassy->certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	// fetch the private key in PEM format and convert to EVP
	bio_memory = BIO_new_mem_buf(privatekey, strlen(privatekey));
	embassy->keyring = PEM_read_bio_PrivateKey(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	embassy->serial = serial;

	return embassy;
}

void pki_write_certificate_in_mem(X509 *certificate, char **certificate_ptr, long *size)
{
	BIO *bio_mem = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio_mem, certificate);

	*size = BIO_get_mem_data(bio_mem, certificate_ptr);
	*(*certificate_ptr + *size) = '\0';

	(void)BIO_set_close(bio_mem, BIO_NOCLOSE);
	BIO_free(bio_mem);
}

void pki_write_privatekey_in_mem(EVP_PKEY *privatekey, char **privatekey_ptr, long *size)
{
	BIO *bio_mem = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio_mem, privatekey, NULL, NULL, 0, 0, NULL);

	*size = BIO_get_mem_data(bio_mem, privatekey_ptr);
	*(*privatekey_ptr + *size) = '\0';

	(void)BIO_set_close(bio_mem, BIO_NOCLOSE);
	BIO_free(bio_mem);
}

int pki_write_certificate(X509 *certificate, const char *filename)
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

int pki_write_privatekey(EVP_PKEY *privatekey, const char *filename)
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

void pki_init()
{
	//SSL_library_init();
	//SSL_load_error_strings();
}

int pki_bootstrap_certs()
{
	uint32_t expiration_delay;
	long size;
	int ret = 0;
	char *cert_ptr, *pvkey_ptr;

	expiration_delay = pki_expiration_delay(10);

	/* switch (nvs) <--> controller (nvc) <--> application (nvp) */
	digital_id_t *nvs_digital_id, *nvc_digital_id, *nvp_digital_id;

	nvs_digital_id = pki_digital_id("netvirt-switch", "", "", "", "admin@netvirt.org", "www.NetVirt.org");
	nvc_digital_id = pki_digital_id("netvirt-controller", "", "", "", "admin@netvirt.org", "www.NetVirt.org");
	nvp_digital_id = pki_digital_id("netvirt-application", "", "", "", "admin@netvirt.org", "www.NetVirt.org");

	embassy_t *nvc_embassy;
	nvc_embassy = pki_embassy_new(nvc_digital_id, expiration_delay);

	passport_t *nvs_passport;
	nvs_passport = pki_embassy_deliver_passport(nvc_embassy, nvs_digital_id, expiration_delay);

	passport_t *nvp_passport;
	nvp_passport = pki_embassy_deliver_passport(nvc_embassy, nvp_digital_id, expiration_delay);

	pki_write_certificate_in_mem(nvc_embassy->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(nvc_embassy->keyring, &pvkey_ptr, &size);

	ret = pki_write_certificate(nvc_embassy->certificate, "/etc/netvirt/certs/netvirt-controller-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-controller-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-controller-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvc_embassy->keyring, "/etc/netvirt/certs/netvirt-controller-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-controller-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-controller-privkey.pem... done\n");
	}

	ret = pki_write_certificate(nvs_passport->certificate, "/etc/netvirt/certs/netvirt-switch-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-switch-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-switch-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvs_passport->keyring, "/etc/netvirt/certs/netvirt-switch-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-switch-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-switch-privkey.pem... done\n");
	}

	ret = pki_write_certificate(nvp_passport->certificate, "/etc/netvirt/certs/netvirt-application-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-application-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-application-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvp_passport->keyring, "/etc/netvirt/certs/netvirt-application-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "/etc/netvirt/certs/netvirt-application-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-application-privkey.pem... done\n");
	}
out:
	pki_embassy_free(nvc_embassy);
	pki_passport_free(nvs_passport);
	pki_passport_free(nvp_passport);

	return 0;
}
