// Passport API
// Copyright (C) Mind4Networks - Benjamin Vanheuverzwijn, 2010

#ifndef DNDS_PASSPORT_H
#define DNDS_PASSPORT_H 1

#include <stdbool.h>
#include <stdint.h>

#include <openssl/ssl.h>

#define KEYTYPE_RSA 1
#define KEYTYPE_DEFAULT KEYTYPE_RSA

#define KEYSIZE_1024 1024
#define KEYSIZE_2048 2048
#define KEYSIZE_4096 4096
#define KEYSIZE_DEFAULT KEYSIZE_2048

#define X509_ENTRY_COUNTRY		"countryName"
#define X509_ENTRY_STATE		"stateOrProvinceName"
#define X509_ENTRY_LOCALITY		"localityName"
#define X509_ENTRY_ORGANIZATION		"organizationName"
#define X509_ENTRY_ORGANIZATIONALUNIT	"organizationalUnitName"
#define X509_ENTRY_COMMON		"commonName"
#define X509_ENTRY_COUNT		6 // Must match the number of entry

struct entry {
	char *key;
	unsigned char *value;
};

/*
 * Passport
 */
typedef struct passport {
    char *certificate_id; // Unique id for a certificate
    X509 *certificate; // OpenSSL X509 certificate
    EVP_PKEY *privatekey; // OpenSSL certificate key
    // FIXME - more?
} passport_t;

/*
 * An embassy delivers passport
 */
typedef struct embassy {
	passport_t *passport;
	X509_STORE *store; // trusted certificate store
	X509_CRL *crl; // certificate status (aka revocation) list
} embassy_t;

// Init the passport module
void passport_init();

/*
 * PASSPORT
 */
// Load a passport from PEM format
passport_t *passport_load(const char *certificate);
// Load a passport from a file containing a certificate in PEM format
passport_t *passport_load_from_file(const char *certificate_path);
// Free a passport object
void passport_free(passport_t *p);
// Set the privatekey on a passport (load from memory, PEM format)
void passport_set_privatekey(passport_t *p, const char *privatekey, const char *password);
// Set the privatekey on a passport (load from file)
void passport_set_privatekey_from_file(passport_t *p, const char *privatekey_path, const char *password);
// Issue a passport
passport_t *passport_issue(embassy_t *a,
		char *country,
		char *state,
		char *locality,
		char *organization,
		char *organizationUnit,
		char *common);
// Revoke a passport
void passport_revoke(embassy_t *a, passport_t *p);
// Verify the validity of a passport
bool passport_verify(embassy_t *a, passport_t *p);
// Export the passport to a string format
int passport_export(passport_t *p, char *buffer, size_t buflen);
// Export the passport private key to a string format
int passport_export_privatekey(passport_t *p, char *buffer, size_t buflen);

/*
 * AMBASSY
 */
// Create an embassy from a passport
embassy_t *embassy_new(passport_t *p);
// Set the certificate store
void embassy_set_store(embassy_t *a);
// Set the certificate revoke list
void embassy_set_crl(embassy_t *a);
// Free an embassy
void embassy_free(embassy_t *pa);

#endif // DNDS_PASSPORT_H
