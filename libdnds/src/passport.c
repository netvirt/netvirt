// Passport API
// Copyright (C) Mind4Networks - Benjamin Vanheuverzwijn, 2010

/* FIXME
 * this subsystem have been obsoleted by pki.c
 */

#include <string.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "passport.h"
#include "journal.h"

/*
 * HELPERS
 */

static void openssl_error_stack() {
	const char *file;
	int line;
	unsigned long e;

	do {
		e = ERR_get_error_line(&file, &line);
		JOURNAL_ERR("openssl]> %s", ERR_error_string(e, NULL));
	} while (e);
}

/*
 * Import a PEM formatted X509 from a bio
 * XXX - it will free the input bio
 */
static X509 *x509_import_pem_from_bio(BIO *input) {
	X509 *x509 = NULL;

	if (input == NULL) {
		JOURNAL_NOTICE("passport]> can't read from a NULL bio");
		return NULL;
	}

	x509 = PEM_read_bio_X509(input, NULL, NULL, NULL);
	BIO_free(input);

	return x509;
}

/*
 * Import a PEM formatted X509 from memory buffer
 */
static X509 *x509_import_pem_from_mem(const char *x509_pem) {
	if (x509_pem == NULL || strlen(x509_pem) <= 0) {
		JOURNAL_NOTICE("passport]> provided x509 in pem format was NULL or empty");
		return NULL;
	}

	return x509_import_pem_from_bio(BIO_new_mem_buf((char *)x509_pem, strlen(x509_pem)));
}

/*
 * Import a PEM formatted X509 from a file
 */
static X509 *x509_import_pem_from_file(const char *x509_pem_path) {
	if (x509_pem_path == NULL || strlen(x509_pem_path) <= 0) {
		JOURNAL_NOTICE("passport]> provided x509 path was NULL or empty");
		return NULL;
	}

	return x509_import_pem_from_bio(BIO_new_file(x509_pem_path, "r"));
}

/*
 * Generate a keypair
 * TODO - need some refactoring.. ugly code is ugly
 */
static EVP_PKEY *key_generate(int type, int size) {
	EVP_PKEY *pkey;
	RSA *rsakey;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		// FIXME - openssl error handling?
		return NULL;
	}

	switch (size) {
		case KEYSIZE_1024:
		case KEYSIZE_2048:
		case KEYSIZE_4096:
			// valid
			break;
		default:
			JOURNAL_NOTICE("passport]> specified keysize is invalid, provided %d", size);
			size = KEYSIZE_DEFAULT;
			break;
	}

	JOURNAL_DEBUG("passport]> generating a key of size %d", size);

	switch (type) {
		case KEYTYPE_RSA:
			JOURNAL_DEBUG("passport]> generating a key of type: RSA");

			rsakey = RSA_generate_key(size, RSA_F4, NULL, NULL); // bit, magic number, callback, cb_arg

			if (!RSA_check_key(rsakey)) {
				JOURNAL_NOTICE("passport]> invalid RSA key, should try again");
				RSA_free(rsakey);
				return NULL;
			}

			if (!EVP_PKEY_set1_RSA(pkey, rsakey)) {
				JOURNAL_NOTICE("passport]> unable to attach RSA key to the PKEY");
				RSA_free(rsakey);
				return NULL;
			}
			break;
		default:
			JOURNAL_NOTICE("passport]> invalid keytype, provided %d", type);
			return NULL;
	}

	return pkey;
}

/*
 * Read a PEM formatted key from a BIO
 * XXX - it will free the input BIO
 */
static EVP_PKEY *key_import_pem_from_bio(BIO *input, const char *password) {
	EVP_PKEY *pkey = NULL;

	if (input == NULL) {
		JOURNAL_NOTICE("passport]> unable to instanciate the BIO to read the key");
		openssl_error_stack();
		return NULL;
	}

	pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, (void *)password);
	BIO_free(input);

	if (pkey == NULL) {
		JOURNAL_ERR("passport]> unable to read the key");
		openssl_error_stack();
		return NULL;
	}

	return pkey;
}

/*
 * Import a key from a file
 */
static EVP_PKEY *key_import_pem_from_file(const char *key_pem_path, const char *password) {
	return key_import_pem_from_bio(BIO_new_file(key_pem_path, "r"), password);
}

/*
 * Import a key from a mem buffer
 */
static EVP_PKEY *key_import_pem_from_mem(const char *key_pem, const char *password) {
	return key_import_pem_from_bio(BIO_new_mem_buf((char *)key_pem, strlen(key_pem)), password);
}

static bool csr_set_entries(X509_REQ *csr, struct entry entries[]) {
	X509_NAME *subject = NULL;
	int i = 0;

	subject = X509_NAME_new();
	if (subject == NULL) {
		JOURNAL_NOTICE("passport]> unable to create a X509_NAME");
		return false;
	}

	for (i=0; i < X509_ENTRY_COUNT; i++) {
		JOURNAL_DEBUG("passport]> adding entry <%s> <%s>", entries[i].key, entries[i].value);

		if (!X509_NAME_add_entry_by_txt(subject, entries[i].key, MBSTRING_ASC, entries[i].value, -1, -1, 0)) {
			JOURNAL_NOTICE("passport]> unable to add entry <%s> <%s>", entries[i].key, entries[i].value);
			openssl_error_stack();
			return false;
		}
	}

	X509_REQ_set_subject_name(csr, subject);

	return true;
}

static X509_REQ *csr_new_key(EVP_PKEY *keypair,
		char *country,
		char *state,
		char *locality,
		char *organization,
		char *organizationalUnit,
		char *common) {

	X509_REQ *csr = NULL;
	const EVP_MD *messagedigest = NULL;
	struct entry entries[X509_ENTRY_COUNT] = {
		{ X509_ENTRY_COUNTRY		, (unsigned char *)country		},
		{ X509_ENTRY_STATE		, (unsigned char *)state		},
		{ X509_ENTRY_LOCALITY		, (unsigned char *)locality		},
		{ X509_ENTRY_ORGANIZATION	, (unsigned char *)organization		},
		{ X509_ENTRY_ORGANIZATIONALUNIT	, (unsigned char *)organizationalUnit	},
		{ X509_ENTRY_COMMON		, (unsigned char *)common		},
	};

	// Creating the Openssl certificate-request
	csr = X509_REQ_new();
	if (csr == NULL) {
		JOURNAL_NOTICE("passport]> unable to create a new X509_REQ");
		openssl_error_stack();
		return NULL;
	}

	if (!csr_set_entries(csr, entries)) {
		JOURNAL_NOTICE("passport]> unable to set entries");
		return NULL;
	}

	X509_REQ_set_pubkey(csr, keypair);

	messagedigest = EVP_sha1();

	// Sign the certificate-request with the private-key
	X509_REQ_sign(csr, keypair, messagedigest);

	return csr;
}

static passport_t *passport_new(X509 *certificate, EVP_PKEY *privatekey) {
	passport_t *p = NULL;

	p = malloc(sizeof(passport_t));
	if (p == NULL) {
		JOURNAL_EMERG("passport]> unable to malloc for a new passport!");
		return NULL;
	}

	p->certificate = certificate;
	p->privatekey = privatekey;

	return p;
}

/*
 * get a unique serial number for the certificates
 * TODO - i think it must be unique... i'm not sure though.
 */
static int get_serial_number() {
	return 1;
}

/*
 * PASSPORT
 */
passport_t *passport_load(const char *certificate) {
	X509 *x509 = NULL;

	if (certificate == NULL || strlen(certificate) <= 0) {
		JOURNAL_ERR("passport]> provided certificate is NULL or empty");
		return NULL;
	}

	x509 = x509_import_pem_from_mem(certificate);
	if (x509 == NULL) {
		JOURNAL_ERR("passport]> unable to load the certificate");
		return NULL;
	}

	return passport_new(x509, NULL);
}

passport_t *passport_load_from_file(const char *certificate_path) {
	X509 *x509 = NULL;

	if (certificate_path == NULL || strlen(certificate_path) <= 0) {
		JOURNAL_ERR("passport]> provided certificate path is NULL or empty");
		return NULL;
	}

	x509 = x509_import_pem_from_file(certificate_path);
	if (x509 == NULL) {
		JOURNAL_ERR("passport]> unable to import X509 certificate from path <%s>", certificate_path);
		return NULL;
	}

	return passport_new(x509, NULL);
}

void passport_free(passport_t *p) {
	if (p != NULL) {
		if (p->certificate != NULL) {
			X509_free(p->certificate);
		}

		free(p);
	}
}

void passport_set_privatekey(passport_t *p, const char *privatekey, const char *password) {
	EVP_PKEY *pkey = NULL;

	if (p == NULL) {
		JOURNAL_ERR("passport]> cannot set the privatekey to a NULL passport");
		return;
	}

	if (privatekey == NULL || strlen(privatekey) <= 0) {
		JOURNAL_ERR("passport]> privatekey is NULL or empty");
		return;
	}

	pkey = key_import_pem_from_mem(privatekey, password);

	if (pkey == NULL) {
		JOURNAL_ERR("passport]> unable to import privatekey into passport");
		return;
	}

	p->privatekey = pkey;
}

void passport_set_privatekey_from_file(passport_t *p, const char *privatekey_path, const char *password) {
	EVP_PKEY *pkey = NULL;

	if (p == NULL) {
		JOURNAL_ERR("passport]> passport is NULL");
		return;
	}

	if (privatekey_path == NULL || strlen(privatekey_path) <= 0) {
		JOURNAL_ERR("passport]> privatekey is NULL or empty");
		return;
	}

	pkey = key_import_pem_from_file(privatekey_path, password);

	if (pkey == NULL) {
		JOURNAL_ERR("passport]> unable to import privatekey into passport");
		return;
	}

	p->privatekey = pkey;
}

/*
 * Issue a passport with the provided embassy
 * If the embassy is NULL, it will generate a self-signed certificate
 */
passport_t *passport_issue(embassy_t *a,
		char *country,
		char *state,
		char *locality,
		char *organization,
		char *organizationalUnit,
		char *common) {

	X509_REQ *csr = NULL;
	X509 *cert = NULL;
	X509_NAME *name = NULL;
	EVP_PKEY *publickey = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *digest;

	// We can now generate a X509 from the CSR
	// TODO - key size and type should be configurable
	pkey = key_generate(KEYTYPE_DEFAULT, KEYSIZE_DEFAULT);
	csr = csr_new_key(pkey,
			country,
			state,
			locality,
			organization,
			organizationalUnit,
			common);

	if (csr == NULL) {
		JOURNAL_ERR("passport]> unable to create the CSR in order to generate the X509");
		openssl_error_stack();
		return NULL;
	}

	cert = X509_new();
	if (cert == NULL) {
		JOURNAL_ERR("passport]> unable to create a new X509");
		openssl_error_stack();
		return NULL;
	}

	// Serial number
	ASN1_INTEGER_set(X509_get_serialNumber(cert), get_serial_number());

	// Subject
	name = X509_REQ_get_subject_name(csr);
	X509_set_subject_name(cert, name);

	// Issuer
	if (a != NULL) {
		// embassy signed
		name = X509_get_subject_name(a->passport->certificate);
	}
	else {
		// self signed
		name = X509_get_subject_name(cert);
	}
	X509_set_issuer_name(cert, name);

	// Public key
	publickey = X509_REQ_get_pubkey(csr);
	X509_set_pubkey(cert, publickey);

	// Invalid before / after
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	// TODO - should be configurable... set to 1 year for now
	X509_gmtime_adj(X509_get_notAfter(cert), (60*60*24*365)); 

	// TODO - x509v3 extensions?

	// LAST STEP:sign the certificate
	if (a != NULL) {
		// embassy signed
		if (!X509_sign(cert, a->passport->privatekey, EVP_sha1())) {
			JOURNAL_ERR("passport]> unable to embassy sign the certificate");
			openssl_error_stack();
			return NULL;
		}
	}
	else {
		// self signed
		if (!X509_sign(cert, pkey, EVP_sha1())) {
			JOURNAL_ERR("passport]> unable to self sign the certificate");
			openssl_error_stack();
			return NULL;
		}
	}

	return passport_new(cert, pkey);
}

void passport_revoke(embassy_t *a, passport_t *p) {
	return;
}

bool passport_verify(embassy_t *a, passport_t *p) {
	return true;
}

/*
 * Export the passport to a pem format in the provided buffer
 * @param p Pointer to the passport you want to export
 * @param buffer A buffer that will contain the exported passport
 * @param buflen Size of the buffer
 * @return Return the size of the passport
 *	o if the return value is greater than 'buflen', nothing has been done
 *		when you should try again with a larger buffer.
 *	o if the return value is lesser than 'buflen', the passport has been
 *		exported successfully
 *	o if the return value is zero, an error occured
 * @note The exported passport is a NULL terminated string and contain a
 *		line return (finish with \n\0)
 */
int passport_export(passport_t *p, char *buffer, size_t buflen) {
	BIO *output;
	char *x509_pem;
	long size;

	output = BIO_new(BIO_s_mem());

	if (!PEM_write_bio_X509(output, p->certificate)) {
		JOURNAL_ERR("passport]> unable to export passport");
		openssl_error_stack();
		BIO_free(output);
		return 0;
	}

	size = BIO_get_mem_data(output, &x509_pem);

	if (size > buflen) {
		return size;
	}

	memcpy(buffer, x509_pem, size);
	buffer[size] = '\0';

	BIO_free(output);
	return size;
}

/*
 * Export the passport private key into a buffer
 */
int passport_export_privatekey(passport_t *p, char *buffer, size_t buflen) {
	return 0;
}

/*
 * AMBASSY
 */

embassy_t *embassy_new(passport_t *p) {
	embassy_t *a = NULL;

	a = malloc(sizeof(embassy_t));
	if (a == NULL) {
		JOURNAL_EMERG("passport]> unable to malloc for a new embassy");
		return NULL;
	}

	a->passport = p;

	// Certificate store (don't forget to mod embassy_free);
	a->store = X509_STORE_new();
	X509_STORE_add_cert(a->store, p->certificate);

	// TODO - crl (don't forget to mod embassy_free);
	a->crl = NULL;

	return a;
}

void embassy_set_store(embassy_t *a) {
	// TODO - fill me
}

void embassy_set_crl(embassy_t *a) {
	// TODO - fill me
}

void embassy_free(embassy_t *a) {
	if (a != NULL) {
		if (a->store != NULL) {
			X509_STORE_free(a->store);
		}

		if (a->crl != NULL) {
			// TODO - free crl
		}

		if (a->passport != NULL) {
			passport_free(a->passport);
		}

		free(a);
	}
}

/*
 * Initialize the passport subsystem. Must be call before everything else in this module.
 */
void passport_init() {
	SSL_library_init();
	SSL_load_error_strings();
}
