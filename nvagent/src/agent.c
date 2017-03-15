/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
 * Nicolas J. Bouliane <nib@m4nt.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>

#include <jansson.h>

#include <pki.h>

#include "agent.h"

static SSL_CTX			*ctx;
static passport_t		*passport;
static struct addrinfo		*ai;

struct event_base	*ev_base = NULL;
int
certverify_cb(int ok, X509_STORE_CTX *store)
{
	X509		*cert;
	X509_NAME	*name;
	char		 buf[256];

	cert = X509_STORE_CTX_get_current_cert(store);
	name = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(name, NID_commonName, buf, 256);

	printf("CN: %s\n", buf);

	return (ok);
}

void
udpclient_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	(void)arg;

	printf("udpclient_cb %d\n", sock);

	SSL     *ssl;
	int      ret;
	char     buf[1500] = {0};

        ssl = arg;

//        if ((ret = SSL_read(ssl, &buf, sizeof(buf))) < 0) {
	while (SSL_connect(ssl) <= 0) {
                ret = SSL_get_error(ssl, ret);
                fprintf(stderr, "SSL_read: error %d (%d-%d)\n", ret, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
                ERR_print_errors_fp(stderr);
		sleep(1);
        }
        SSL_write(ssl, "hello", 4);
        fprintf(stderr, "%s %d", buf, ret);
}

void
http_prov_cb(struct evhttp_request *req, void *arg)
{
	json_t			*jmsg;
	json_error_t		 error;
	struct evbuffer         *buf;
	const char		*cacert;
	const char		*cert;
        void                    *p;

	buf = evhttp_request_get_input_buffer(req);

        p = evbuffer_pullup(buf, -1);

	if ((jmsg = json_loadb(p, evbuffer_get_length(buf), 0, &error)) == NULL) {
		log_warnx("%s: json_loadb - %s", __func__, error.text);
		goto err;
	}

	if (json_unpack(jmsg, "{s:s,s:s}", "cert", &cert, "cacert", &cacert)
	    < 0) {
		log_warnx("%s: json_unpack", __func__);
		goto err;
	}

	printf("%s\n", cert);
	printf("%s\n", cacert);

	FILE *fcert, *fcacert;
	fcert = fopen("/etc/netvirt/certs/netvirt-app-cert.pem", "w");
	fcacert = fopen("/etc/netvirt/certs/netvirt-app-cacert.pem", "w");

	fwrite(cert, strlen(cert), 1, fcert);
	fwrite(cacert, strlen(cacert), 1, fcacert);

	fclose(fcert);
	fclose(fcacert);
err:
	return;

}

int
agent_prov(const char *provkey)
{

	EVP_PKEY	*keyring = NULL;
	X509_REQ	*certreq = NULL;
	digital_id_t	*nva_id = NULL;
	long		 size = 0;
	char		*certreq_pem = NULL;
	char		*pvkey_pem = NULL;

	nva_id = pki_digital_id("",  "", "", "", "contact@dynvpn.com", "www.dynvpn.com");

	/* generate RSA public and private keys */
	keyring = pki_generate_keyring();

	pki_write_privatekey(keyring, "/etc/netvirt/certs/netvirt-app-privkey.pem"); 

	/* create a certificate signing request */
	certreq = pki_certificate_request(keyring, nva_id);

	/* write the certreq in PEM format */
	pki_write_certreq_in_mem(certreq, &certreq_pem, &size);

	/* write the private key in PEM format */
	pki_write_privatekey_in_mem(keyring, &pvkey_pem, &size);

//	printf("certrq_pem: %s]\n\n", certreq_pem);
//	printf("pvkey_pem: %s]\n\n", pvkey_pem);


	struct evhttp_connection	*evhttp_conn;
	struct evhttp_request		*req;
	struct evkeyvalq		*output_headers;
	struct evbuffer			*output_buffer;
	char				*content_buffer;
	int				 length;

	evhttp_conn = evhttp_connection_base_new(ev_base, NULL, "127.0.0.1", 8080);
	req = evhttp_request_new(http_prov_cb, NULL);

	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Content-Type", "application/json");

	json_t *jresp;
	char *resp;

        jresp = json_object();
        json_object_set_new(jresp, "csr", json_string(certreq_pem));
	json_object_set_new(jresp, "provkey", json_string(provkey));
        resp = json_dumps(jresp, 0);

	printf("resp: %s\n", resp);

	output_buffer = evhttp_request_get_output_buffer(req);
	evbuffer_add(output_buffer, resp, strlen(resp));

	evhttp_make_request(evhttp_conn, req, EVHTTP_REQ_POST, "/v1/provisioning");

        
	return (0);
}


int
agent_init(void)
{
	BIO		*bio = NULL;
	SSL		*ssl = NULL;
	EC_KEY		*ecdh;
	struct event	*ev_udpclient;
	struct addrinfo	 hints;
	int		 status;
	int		 sock;
	int		 flag;
	int		 ret;
	const char	*ip = "127.0.0.1";
	const char	*port = "9090";
	const char	*cert = "/etc/netvirt/certs/netvirt-app-cert.pem";
	const char	*pkey = "/etc/netvirt/certs/netvirt-app-privkey.pem";
	const char	*trust_cert = "/etc/netvirt/certs/netvirt-app-cacert.pem";

	if ((ev_base = event_base_new()) == NULL)
		errx(1, "event_base_new");

	SSL_library_init();
	SSL_load_error_strings();

//	if (!RAND_poll())
//		err(1, "%s:%d", "RAND_poll", __LINE__);

	if ((ctx = SSL_CTX_new(DTLSv1_client_method())) == NULL)
		errx(1, "%s:%d", "SSL_CTX_new", __LINE__);

//	if ((passport = pki_passport_load_from_file(cert, pkey, trust_cert)) == NULL)
//		err(1, "%s:%d", "pki_passport_load_from_file", __LINE__);

	/* Load the trusted certificate store into our SSL_CTX */
//	SSL_CTX_set_cert_store(ctx, passport->cacert_store);

	/* Set the certificate and key */
//	SSL_CTX_use_certificate(ctx, passport->certificate);
//	SSL_CTX_use_PrivateKey(ctx, passport->keyring);

//	if ((ret = SSL_CTX_set_cipher_list(ctx, "AES256-SHA")) == 0)
//		err(1, "%s:%d", "SSL_CTX_set_cipher_list", __LINE__);

//	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
//		err(1, "%s:%d", "EC_KEY_new_by_curve_name", __LINE__);

//	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
//	EC_KEY_free(ecdh);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		errx(1, "%s:%s:%d", "getaddrinfo", gai_strerror(status), __LINE__);

	if ((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
		errx(1, "%s:%d", "socket", __LINE__);

	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		errx(1, "%s:%d", "setsockopt", __LINE__);

	if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		warn("%s:%d", "connect", __LINE__);

	if ((ssl = SSL_new(ctx)) == NULL)
		warnx("%s:%d", "SSL_new", __LINE__);

//	SSL_set_tlsext_host_name(ssl, "W1mOpl6pYICUB1-Il8B26HlP");
//	SSL_set_verify(ssl,
//	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);

	if ((bio = BIO_new_dgram(sock, BIO_NOCLOSE)) == NULL)
		warnx("%s:%d", "BIO_new_dgram", __LINE__);

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ai->ai_addr);

	SSL_set_bio(ssl, bio, bio);

	if (evutil_make_socket_nonblocking(sock) > 0)
		err(1, "%s:%d", "evutil_make_socket_nonblocking", __LINE__);

	char buf[1500] = {0};

	SSL_set_connect_state(ssl);
	if ((ret = SSL_connect(ssl)) <= 0) {
//        if ((ret = SSL_read(ssl, &buf, sizeof(buf))) < 0) {
       //if ((ret = SSL_write(ssl, "hello", 4)) < 0) {
		ret = SSL_get_error(ssl, ret);
		fprintf(stderr, "SSL_read: error %d (%d-%d)\n", ret, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
		ERR_print_errors_fp(stderr);
		warn("ssl_connect");
	}
	printf("after\n");
	if ((ev_udpclient = event_new(ev_base, sock,
	    EV_READ | EV_PERSIST, udpclient_cb, ssl)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
	event_add(ev_udpclient, NULL);

	event_base_dispatch(ev_base);
	return (0);
}

void
agent_fini()
{

}

