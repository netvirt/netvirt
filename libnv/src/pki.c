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

// XXX refactor this file

#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "pki.h"

// openssl x509 -in ./certificate.pem -text


// XXX still needed ?
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

void
certinfo_destroy(struct certinfo *ci)
{
	free(ci->version);
	free(ci->type);
	free(ci->network_uid);
	free(ci->node_uid);
	free(ci);
}

struct certinfo
*certinfo(X509 *cert)
{
	X509_NAME	*subj;
	struct certinfo	*ci;
	size_t		 i;
	char		 cn[64];
	char		*tokens[5];
	char		*tok;
	char		*last;

	if ((subj = X509_get_subject_name(cert)) == NULL) {
		log_warnx("%s: X509_get_subject_name", __func__);
		return (NULL);
	}

	if (X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn)) < 0) {
		log_warnx("%s: X509_NAME_get_text_by_NID", __func__);
		return (NULL);
	}

	for ((i = 0, tok = strtok_r(cn, ":", &last)); tok;
	    (tok = strtok_r(NULL, ":", &last))) {
		if (i < sizeof(tokens)) {
			tokens[i++] = tok;
		}
	}
	tokens[i] = NULL;

	if (tokens[0] == NULL ||
	    tokens[1] == NULL ||
	    tokens[2] == NULL ||
	    tokens[3] == NULL) {
		log_warnx("%s: token is NULL", __func__);
		return (NULL);
	}

	if ((ci = malloc(sizeof(struct certinfo))) == NULL) {
		log_warnx("%s: malloc", __func__);
		return (NULL);
	}

	ci->version = strdup(tokens[0]);
	ci->type = strdup(tokens[1]);
	ci->network_uid = strdup(tokens[2]);
	ci->node_uid = strdup(tokens[3]);

	return (ci);
}

void pki_passport_destroy(passport_t *passport)
{
	if (passport == NULL)
		return;

	EVP_PKEY_free(passport->keyring);
	X509_free(passport->certificate);
	X509_free(passport->cacert);
	X509_STORE_free(passport->cacert_store);
	certinfo_destroy(passport->certinfo);
	free(passport);
}

passport_t *pki_passport_load_from_memory(const char *cert, const char *pvkey,
    const char *cacert)
{
	BIO *bio_memory = NULL;
	passport_t *passport;

	// create an empty passport
	passport = calloc(1, sizeof(passport_t));

	// fetch the certificate in PEM format and convert to X509
	bio_memory = BIO_new_mem_buf((void *)cert, strlen(cert));
	passport->certificate = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	// fetch the private key in PEM format and convert to EVP
	bio_memory = BIO_new_mem_buf((void *)pvkey, strlen(pvkey));
	passport->keyring = PEM_read_bio_PrivateKey(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	// fetch the certificate authority in PEM format convert to X509
	// and add to the trusted store
	bio_memory = BIO_new_mem_buf((void *)cacert, strlen(cacert));
	passport->cacert = PEM_read_bio_X509(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);
	passport->cacert_store = X509_STORE_new();
	X509_STORE_add_cert(passport->cacert_store, passport->cacert);

	passport->certinfo = certinfo(passport->certificate);

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


void
pki_get_pubkey(X509 *cert, char **pubkey_pem, long *size)
{
	BIO *bio_mem = NULL;
	EVP_PKEY *pubkey = NULL;

	pubkey = X509_get_pubkey(cert);

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio_mem, pubkey);

	*size = BIO_get_mem_data(bio_mem, pubkey_pem);

	(void)BIO_set_close(bio_mem, BIO_NOCLOSE);
	BIO_free(bio_mem);
}

EVP_PKEY 
*pki_generate_keyring()
{
	EVP_PKEY_CTX	*params_ctx, *key_ctx;
	EVP_PKEY	*keyring = NULL, *params = NULL;
	EC_KEY		*pubkey;

	OpenSSL_add_all_algorithms();
	RAND_poll();

	params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	EVP_PKEY_paramgen_init(params_ctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params_ctx, NID_X9_62_prime256v1);

	EVP_PKEY_paramgen(params_ctx, &params);

	key_ctx = EVP_PKEY_CTX_new(params, NULL);
	EVP_PKEY_keygen_init(key_ctx);
	EVP_PKEY_keygen(key_ctx, &keyring);

	pubkey = EVP_PKEY_get1_EC_KEY(keyring);
	EC_KEY_set_asn1_flag(pubkey, OPENSSL_EC_NAMED_CURVE);

	return keyring;

}
/*
static EVP_PKEY *pki_generate_rsa_keyring()
{
	//jlog(L_DEBUG, "pki_generate_keyring");

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
*/
X509_REQ 
*pki_certificate_request(EVP_PKEY *keyring, digital_id_t *digital_id)
{
	//jlog(L_DEBUG, "pki_certificate_request");

	X509_REQ *cert_req;
	X509_NAME *subject;
	X509_EXTENSION *ext;
	STACK_OF(X509_EXTENSION) *extlist;
	const EVP_MD *message_digest;

	// create a certificate request
	cert_req = X509_REQ_new();

		extlist = sk_X509_EXTENSION_new_null();
		ext = X509V3_EXT_conf(NULL, NULL, "subjectAltName", digital_id->altName);
		sk_X509_EXTENSION_push(extlist, ext);
		X509_REQ_add_extensions(cert_req, extlist);
		sk_X509_EXTENSION_pop_free(extlist, X509_EXTENSION_free);

	// set certificate request 'Subject:'
	subject = X509_NAME_new();
	X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, (unsigned char*)digital_id->commonName, -1, -1, 0);
	X509_REQ_set_subject_name(cert_req, subject);
	X509_NAME_free(subject);

	// set certificate request public key
	X509_REQ_set_pubkey(cert_req, keyring);

	// create a message digest
	message_digest = EVP_sha256();

	// sign certificate request
	X509_REQ_sign(cert_req, keyring, message_digest);

	return cert_req;
}

static X509 *
pki_certificate(X509_NAME *issuer, X509_REQ *certreq,
	    uint8_t is_CA, uint32_t serial, uint32_t expire)
{
	//jlog(L_DEBUG, "pki_certificate");

	EVP_PKEY	*pub_key = NULL;
	X509		*certificate;
	X509_NAME	*subject;

	X509V3_CTX ctx;
	X509_EXTENSION *ext;

	/* verify CSR signature */
	if ((pub_key = X509_REQ_get_pubkey(certreq)) == NULL)
		return (NULL);

	if (X509_REQ_verify(certreq, pub_key) != 1)
		return (NULL);
	
	/* create a new certificate */
	certificate = X509_new();

	/* set certificate unique serial number */
	ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial);

	/* set certificate 'Subject:' */
	subject = X509_REQ_get_subject_name(certreq);
	X509_set_subject_name(certificate, subject);

	/* Subject Alternative Name */
	int subjAltName_pos;
	STACK_OF(X509_EXTENSION) *req_exts;
	X509_EXTENSION *subjAltName;

	if ((req_exts = X509_REQ_get_extensions(certreq)) != NULL) {
		subjAltName_pos = X509v3_get_ext_by_NID(req_exts, OBJ_sn2nid("subjectAltName"), -1);
		subjAltName = X509v3_get_ext(req_exts, subjAltName_pos);
		X509_add_ext(certificate, subjAltName, -1);
	}

	/* set certificate 'Issuer:' */
	X509_set_issuer_name(certificate, issuer);

	/* set X509v3 extension "basicConstraints" CA:TRUE/FALSE */
	X509V3_set_ctx(&ctx, NULL, certificate, certreq, NULL, 0);

	if (is_CA == true)
		ext = X509V3_EXT_conf(NULL, &ctx, "basicConstraints", "CA:TRUE");
	else
		ext = X509V3_EXT_conf(NULL, &ctx, "basicConstraints", "CA:FALSE");

	X509_add_ext(certificate, ext, -1);
	X509_EXTENSION_free(ext);

	/* set certificate version 3 */
	X509_set_version(certificate, 0x2);

	/* set certificate public key */
	X509_set_pubkey(certificate, pub_key);

	/* set the 'notBefore' to yersterday */
	X509_gmtime_adj(X509_get_notBefore(certificate), -(24*60*60));

	/* set certificate expiration delay */
	X509_gmtime_adj(X509_get_notAfter(certificate), expire);

	return certificate;
}

static void pki_sign_certificate(EVP_PKEY *keyring, X509 *certificate)
{
	//jlog(L_NOTICE, "pki_sign_certificate");

	X509_sign(certificate, keyring, EVP_sha256());
}

static void b64enc(const uint8_t *buf, size_t length, char **b64buf)
{
	BIO	*bio = NULL;
	BIO	*b64 = NULL;
	BUF_MEM	*memptr = NULL;
	char	*p;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buf, length);
	(void)BIO_flush(bio);

	BIO_get_mem_ptr(bio, &memptr);
	(void)BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64buf = calloc(1, memptr->length+1);
	strncpy(*b64buf, memptr->data, memptr->length);

	*(*b64buf + (memptr->length)) = '\0';

	p = *b64buf;
	while (*p != '\0') {
		if (*p == '/')
			*p = '_';
		else if (*p == '+')
			*p = '-';
		p++;
	}

	BUF_MEM_free(memptr);
}

char *
pki_gen_uid()
{
	int ret = 0;

	char *b64key = NULL;
	uint8_t key[18];

	ret = RAND_bytes(key, sizeof(key));
	if (ret != 1) {
		return (NULL);
	}

	b64enc(key, sizeof(key), &b64key);

	return b64key;
}


char *pki_gen_key()
{
	int ret = 0;

	char *b64key = NULL;
	uint8_t key[36];

	ret = RAND_bytes(key, 36);
	if (ret != 1) {
		return NULL;
	}

	b64enc(key, 36, &b64key);

	return b64key;
}

// XXX still needed ?
void pki_free_digital_id(digital_id_t *digital_id)
{
	if (digital_id == NULL)
		return;

	free(digital_id->commonName);
	free(digital_id->altName);
	free(digital_id->stateOrProvinceName);
	free(digital_id->localityName);
	free(digital_id->emailAddress);
	free(digital_id->organizationName);

	free(digital_id);
}

// XXX still needed ?
digital_id_t *pki_digital_id(char *commonName,
				char *altName,
				char *stateOrProvinceName,
				char *localityName,
				char *emailAddress,
				char *organizationName)
{
	//jlog(L_DEBUG, "pki_digital_id");

	digital_id_t *digital_id;
	digital_id = calloc(1, sizeof(digital_id_t));

	digital_id->commonName = strdup(commonName);
	digital_id->altName = strdup(altName);
	digital_id->localityName = strdup(localityName);
	digital_id->stateOrProvinceName = strdup(stateOrProvinceName);
	digital_id->emailAddress = strdup(emailAddress);
	digital_id->organizationName = strdup(organizationName);

	return digital_id;
}

void pki_embassy_free(embassy_t *embassy)
{
	if (embassy == NULL)
		return;

	X509_free(embassy->certificate);
	EVP_PKEY_free(embassy->keyring);
	free(embassy);
}

embassy_t *pki_embassy_new(digital_id_t *digital_id, uint32_t expiration_delay)
{
	//jlog(L_NOTICE, "pki_embassy_new");

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
	certificate = pki_certificate(issuer, cert_req, true, serial++, expiration_delay);
	X509_REQ_free(cert_req);

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
	if (passport == NULL)
		return;

	X509_free(passport->certificate);
	EVP_PKEY_free(passport->keyring);
	X509_free(passport->cacert);
	X509_STORE_free(passport->cacert_store);

	free(passport);
}

passport_t *pki_embassy_deliver_passport(embassy_t *embassy, digital_id_t *digital_id, uint32_t expiration_delay)
{
	//jlog(L_NOTICE, "pki_embassy_deliver_passport");

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
	certificate = pki_certificate(issuer, cert_req, false, embassy->serial++, expiration_delay);
	X509_REQ_free(cert_req);

	// sign the certificate with the certificate authority
	pki_sign_certificate(embassy->keyring, certificate);

	// create the new passport
	passport->certificate = certificate;
	passport->keyring = keyring;
	passport->cacert_store = X509_STORE_new();

	// add the trusted certificate authority
	X509_STORE_add_cert(passport->cacert_store, embassy->certificate);

	// deliver the passport
	return passport;
}

char *
pki_deliver_cert_from_certreq(char *certreq_pem, char *emb_cert, char *emb_pvkey, uint32_t emb_serial, const char *cn)
{
        X509		*cert = NULL;
        X509_NAME	*issuer = NULL;
        X509_REQ	*certreq = NULL;
        embassy_t	*embassy = NULL;
        long		 cert_pem_len = 0;
        int		 exp_delay = 0;
        char		*cert_pem = NULL;

        /* convert from PEM format */
        certreq = pki_csr_load_from_memory(certreq_pem);

        /* load embassy object */
        embassy = pki_embassy_load_from_memory(emb_cert, emb_pvkey, emb_serial);

        exp_delay = pki_expiration_delay(10);

        /* extract issuer from CA certificate */
        issuer = X509_get_subject_name(embassy->certificate);

        cert = pki_certificate(issuer, certreq, false, embassy->serial, exp_delay);

	/* set certificate request 'Subject:' */
	X509_NAME *subject = X509_NAME_new();
	X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);
	X509_set_subject_name(cert, subject);
	X509_NAME_free(subject);

        pki_sign_certificate(embassy->keyring, cert);

        /* convert to PEM format */
        pki_write_certificate_in_mem(cert, &cert_pem, &cert_pem_len);

        return (cert_pem);
}


uint32_t pki_expiration_delay(uint8_t years)
{
	// if years > 68, it will overflow the certificate 'Not After Date'
	// dont be silly, we will never need more than 68 years !
	if (years > 68)
		years = 68;

	return years*365*24*60*60;
}

X509_REQ *
pki_csr_load_from_memory(char *certreq_pem)
{
	BIO *bio_memory = NULL;
	X509_REQ *certreq = NULL;

	bio_memory = BIO_new_mem_buf(certreq_pem, strlen(certreq_pem));
	certreq = PEM_read_bio_X509_REQ(bio_memory, NULL, NULL, NULL);
	BIO_free(bio_memory);

	return certreq;
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

void pki_write_certificate_in_mem(X509 *certificate, char **certificate_ptr, long *size)
{
	char *pp = NULL;
	BIO *bio_mem = NULL;
	*certificate_ptr = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio_mem, certificate);

	*size = BIO_get_mem_data(bio_mem, &pp);
	if (pp != NULL) {
		*(pp + *size) = '\0';
		*certificate_ptr = strdup(pp);
	}

	BIO_free(bio_mem);
}

void pki_write_privatekey_in_mem(EVP_PKEY *privatekey, char **privatekey_ptr, long *size)
{
	char *pp = NULL;
	BIO *bio_mem = NULL;
	*privatekey_ptr = NULL;

	bio_mem = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio_mem, privatekey, NULL, NULL, 0, 0, NULL);

	*size = BIO_get_mem_data(bio_mem, &pp);
	if (pp != NULL) {
		*(pp + *size) = '\0';
		*privatekey_ptr = strdup(pp);
	}

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

	nvs_digital_id = pki_digital_id("netvirt-switch", "", "", "", "admin@netvirt.org", "www.netvirt.org");
	nvc_digital_id = pki_digital_id("netvirt-ctrler", "", "", "", "admin@netvirt.org", "www.vetvirt.org");
	nvp_digital_id = pki_digital_id("netvirt-app", "", "", "", "admin@netvirt.org", "www.netvirt.org");

	embassy_t *nvc_embassy;
	nvc_embassy = pki_embassy_new(nvc_digital_id, expiration_delay);
	passport_t *nvs_passport;
	nvs_passport = pki_embassy_deliver_passport(nvc_embassy, nvs_digital_id, expiration_delay);
	passport_t *nvp_passport;
	nvp_passport = pki_embassy_deliver_passport(nvc_embassy, nvp_digital_id, expiration_delay);
	pki_write_certificate_in_mem(nvc_embassy->certificate, &cert_ptr, &size);
	pki_write_privatekey_in_mem(nvc_embassy->keyring, &pvkey_ptr, &size);

	ret = pki_write_certificate(nvc_embassy->certificate, "/etc/netvirt/certs/netvirt-ctrler-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-ctrler-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-ctrler-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvc_embassy->keyring, "/etc/netvirt/certs/netvirt-ctrler-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-ctrler-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-ctrler-privkey.pem... done\n");
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

	ret = pki_write_certificate(nvp_passport->certificate, "/etc/netvirt/certs/netvirt-app-cert.pem");
	if (ret == -1) {
		fprintf(stderr, "can't write: /etc/netvirt/certs/netvirt-app-cert.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-app-cert.pem... done\n");
	}
	ret = pki_write_privatekey(nvp_passport->keyring, "/etc/netvirt/certs/netvirt-app-privkey.pem");
	if (ret == -1) {
		fprintf(stderr, "/etc/netvirt/certs/netvirt-app-privkey.pem\n");
		goto out;
	} else {
		fprintf(stdout, "/etc/netvirt/certs/netvirt-app-privkey.pem... done\n");
	}
out:
	pki_embassy_free(nvc_embassy);
	pki_passport_free(nvs_passport);
	pki_passport_free(nvp_passport);

	return 0;
}
