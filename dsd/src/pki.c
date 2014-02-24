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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "logger.h"
#include "pki.h"

// openssl x509 -in ./certificate.pem -text

/* TODO 
 * handle errors
 * use journal instead of printf
 */

static EVP_PKEY *pki_generate_keyring()
{
	jlog(L_NOTICE, "pki_generate_keyring\n");

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
	jlog(L_NOTICE, "pki_certificate_request\n");

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
	jlog(L_NOTICE, "pki_certificate\n");

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
	jlog(L_NOTICE, "pki_sign_certificate\n");

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
	jlog(L_NOTICE, "pki_digital_id\n");

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
	jlog(L_NOTICE, "pki_embassy_new\n");

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
	jlog(L_NOTICE, "pki_embassy_deliver_passport\n");

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

void pki_write_certificate(X509 *certificate, const char *filename)
{
	BIO *bio_file = NULL;

	bio_file = BIO_new_file(filename, "w");
	PEM_write_bio_X509(bio_file, certificate);

	BIO_free(bio_file);
}

void pki_write_privatekey(EVP_PKEY *privatekey, const char *filename)
{
	BIO *bio_file = NULL;

	bio_file = BIO_new_file(filename, "w");
	PEM_write_bio_PrivateKey(bio_file, privatekey, NULL, NULL, 0, 0, NULL);

	BIO_free(bio_file);
}

void pki_init()
{
	//SSL_library_init();
	//SSL_load_error_strings();
}
/*
int main()
{
	pki_init();

	uint32_t expiration_delay;
	expiration_delay = pki_expiration_delay(50);

	// DND <--> DSD <--> DSC
	digital_id_t *dsd_digital_id, *dnd_digital_id, *dsc_digital_id;

	dsd_digital_id = pki_digital_id("dsd-master", "CA", "Quebec",
					"Levis", "info@demo.com", "DNDS");

	dnd_digital_id = pki_digital_id("dnd-0", "CA", "Quebec",
					"Levis", "info@demo.com", "DNDS");

	dsc_digital_id = pki_digital_id("demo@1", "", "",
					"", "client@demo", "demo");

	embassy_t *dsd_embassy;
	dsd_embassy = pki_embassy_new(dsd_digital_id, expiration_delay);

	passport_t *dnd_passport;
	dnd_passport = pki_embassy_deliver_passport(dsd_embassy, dnd_digital_id, expiration_delay);

	passport_t *dsc_passport;
	dsc_passport = pki_embassy_deliver_passport(dsd_embassy, dsc_digital_id, expiration_delay);


	char *cert_ptr; long size;
	char *pvkey_ptr;

	pki_write_certificate_in_mem(dsd_embassy->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(dsd_embassy->keyring, &pvkey_ptr, &size);

	jlog(L_NOTICE, "cert %s\n", cert_ptr);
	jlog(L_NOTICE, "pvkey %s\n", pvkey_ptr);

	return 0;

	pki_write_certificate(dsd_embassy->certificate, "./dsd_cert.pem");
	pki_write_privatekey(dsd_embassy->keyring, "dsd_privkey.pem");

	pki_write_certificate(dnd_passport->certificate, "./dnd_cert.pem");
	pki_write_privatekey(dnd_passport->keyring, "./dnd_privkey.pem");

	pki_write_certificate(dsc_passport->certificate, "./dsc_cert.pem");
	pki_write_privatekey(dsc_passport->keyring, "./dsc_privkey.pem");


	// DNC <--> DND
	digital_id_t *embassy_demo_id, *dnd_demo_id, *dnc_demo_id;

	embassy_demo_id = pki_digital_id("embassy@2", "CA", "Quebec",
					"Levis", "nib@dynvpn.com", "M4Nt inc");

	dnd_demo_id = pki_digital_id("dnd@2", "CA", "Quebec",
					"Levis", "nib@dynvpn.com", "M4Nt inc");

	dnc_demo_id = pki_digital_id("dnc@2", "CA", "Quebec",
					"", "nib@dynvpn.com", "M4Nt inc");

	embassy_t *embassy_demo;
	embassy_demo = pki_embassy_new(embassy_demo_id, expiration_delay);

	passport_t *dnd_passport_demo;
	dnd_passport_demo = pki_embassy_deliver_passport(embassy_demo, dnd_demo_id, expiration_delay);

	passport_t *dnc_passport_demo;
	dnc_passport_demo = pki_embassy_deliver_passport(embassy_demo, dnc_demo_id, expiration_delay);

	pki_write_certificate(embassy_demo->certificate, "./embassy_demo_cert.pem");
	pki_write_privatekey(embassy_demo->keyring, "./embassy_demo_privkey.pem");

	pki_write_certificate(dnd_passport_demo->certificate, "./dnd_demo_cert.pem");
	pki_write_privatekey(dnd_passport_demo->keyring, "./dnd_demo_privkey.pem");

	pki_write_certificate(dnc_passport_demo->certificate, "./dnc_demo_cert.pem");
	pki_write_privatekey(dnc_passport_demo->keyring, "./dnc_demo_privkey.pem");

	// free
	pki_passport_free(dnd_passport);
	pki_passport_free(dsc_passport);
	pki_embassy_free(dsd_embassy);

	pki_passport_free(dnc_passport_demo);
	pki_passport_free(dnd_passport_demo);
	pki_embassy_free(embassy_demo);

	return 0;
}
*/
