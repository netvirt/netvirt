#ifndef DNDS_KRYPT_H
#define DNDS_KRYPT_H

#include <stdint.h>
#include <openssl/ssl.h>

#include "netbus.h"

#define KRYPT_TLS	0x1	// Transport Layer Security { NET_TCP, NET_UDT }
#define KRYPT_DTLS	0x2	// Datagram Transport Layer Security { unused }

#define KRYPT_CLIENT	0x1	// Connection type Client
#define KRYPT_SERVER	0x2	// Connection type Server

#define KRYPT_NOINIT	0x1	// Connection status Not Initialized
#define KRYPT_HANDSHAKE 0x2	// Connection status Handshaking
#define KRYPT_SECURE	0x4	// Conecction status Secure
#define KRYPT_FAIL	0x8	// Connection status Fail, something went wrong during the handshake

#define KRYPT_ADH	0x1	// Basic security level ADH
#define KRYPT_RSA	0x2	// Maximum security level RSA

typedef struct passport {

        X509 *certificate;
        EVP_PKEY *keyring;
        X509_STORE *trusted_authority;
} passport_t;

typedef struct krypt {

	SSL *ssl;			// SSL Connection
	SSL_CTX *ctx;			// SSL Context

	STACK_OF(X509_NAME) *cert_name;	// Certificate CommonName

	BIO *internal_bio;		// used to bridge Network and SSL non-blocking operations
	BIO *network_bio;		// BIO is a I/O abstraction provided by openSSL

	passport_t *passport;		// Certificate and key used to negotiate RSA
	char client_cn[256];		// Client certificate commonName

	uint8_t security_level;		// Security level negotiated { ADH, RSA }
	uint8_t status;			// Status { NOINIT, HANDSHAKE, SECURE, FAIL }
	uint8_t conn_type;

	uint8_t *buf_decrypt;		// Decrypted data
	size_t buf_decrypt_size;	// Buffer size in memory
	size_t buf_decrypt_data_size;	// Data size in the buffer

	uint8_t *buf_encrypt;		// Encrypted data
	size_t buf_encrypt_size;	// Buffer size in memory
	size_t buf_encrypt_data_size;	// Data size in the buffer

} krypt_t;

passport_t *pki_passport_load_from_memory(char *certificate, char *privatekey, char *trusted_authority);
passport_t *pki_passport_load_from_file(char *certificate_filename,
                                        char *privatekey_filename,
                                        char *trusted_authority_filename);
void krypt_set_renegotiate(krypt_t *kconn);
int krypt_set_rsa(krypt_t *kconn);
int krypt_step_up(krypt_t *kconn);
int krypt_encrypt_buf(krypt_t *kcon, uint8_t *buf, size_t buf_data_size);
int krypt_push_encrypted_data(krypt_t *kconn, uint8_t *buf, size_t buf_data_size);
int krypt_decrypt_buf(krypt_t *kconn, uint8_t *buf, size_t buf_data_size);
int krypt_do_handshake(krypt_t *kconn, uint8_t *buf, size_t buf_data_size);
int krypt_secure_connection(krypt_t *kconn, uint8_t protocol, uint8_t state, uint8_t security_level);
void krypt_add_passport(krypt_t *kconn, passport_t *passport);

void krypt_fini();
int krypt_init();

#endif /* DNDS_KRYPT_H */
