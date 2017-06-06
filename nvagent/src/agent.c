/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2017 Mind4Networks inc.
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
#include <sys/stat.h>
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
#include <tapcfg.h>

#include "agent.h"

struct prov_info {
	const char	*network_name;
	const char	*pvkey;
};

enum dtls_state {
	DTLS_CONNECT,
	DTLS_ESTABLISHED
};

struct dtls_peer {
	struct event	*timer;
	enum dtls_state	 state;
	SSL		*ssl;
	tapcfg_t	*tapcfg;
	int		 sock;
};

static SSL_CTX			*ctx;
static passport_t		*passport;
static struct addrinfo		*ai;
struct event_base		*ev_base;
struct dtls_peer		 switch_peer;

static int	 certverify_cb(int, X509_STORE_CTX *);
static void	 dtls_peer_free(struct dtls_peer *);
static void	 dtls_peer_timeout_cb(int, short, void *);
static int	 dtls_handle(struct dtls_peer *);
static void	 iface_cb(int, short, void *);
static void	 udpclient_cb(int, short, void *);
static void	 http_prov_cb(struct evhttp_request *, void *);

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
dtls_peer_free(struct dtls_peer *p)
{

}

void
dtls_peer_timeout_cb(int fd, short event, void *arg)
{
	(void)fd;
	(void)event;

	struct dtls_peer	*p = arg;

	DTLSv1_handle_timeout(p->ssl);

	if (dtls_handle(p) < 0) {
		dtls_peer_free(p);
	}
}

int
dtls_handle(struct dtls_peer *p)
{
	struct timeval	tv;
	enum dtls_state	next_state;
	int		ret;
	char		buf[1500] = {0};

	for (;;) {

		switch (p->state) {
		case DTLS_CONNECT:
			ret = SSL_do_handshake(p->ssl);
			next_state = DTLS_ESTABLISHED;
			break;

		case DTLS_ESTABLISHED:
			ret = SSL_read(p->ssl, buf, sizeof(buf));
			next_state = DTLS_ESTABLISHED;
			break;

		default:
			fprintf(stderr, "%s: invalid DTLS peer state\n", __func__);
			return (-1);
		}

		switch (SSL_get_error(p->ssl, ret)) {
		case SSL_ERROR_NONE:
			break;

		case SSL_ERROR_WANT_WRITE:
			return (0);

		case SSL_ERROR_WANT_READ:
			if (DTLSv1_get_timeout(p->ssl, &tv) == 1 &&
			    evtimer_add(p->timer, &tv) < 0) {
				return (-1);
			}
			return (0);

		default:
			fprintf(stderr, "%s: ssl error\n", __func__);
			return (-1);
		}

		p->state = next_state;
	}

	return (0);
}

void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;

	struct dtls_peer	*p;
	int			 ret;
	char			 buf[1500] = {0};

	p = arg;

	printf("iface_cb\n");

	ret = tapcfg_read(p->tapcfg, buf, sizeof(buf));
	// XXX verify ret

	if (p->state == DTLS_ESTABLISHED) {
		printf("write !\n");
		SSL_write(p->ssl, buf, ret);
	}
}

void
udpclient_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	(void)arg;

	struct dtls_peer	*p = arg;

	if (what&EV_TIMEOUT || dtls_handle(p) < 0)
		goto error;

	return;

error:
	dtls_peer_free(p);
}

void
http_prov_cb(struct evhttp_request *req, void *arg)
{
	json_t			*jmsg;
	json_error_t		 error;
	struct evbuffer         *buf;
	struct prov_info	*prov_info;
	const char		*cacert;
	const char		*cert;
        void                    *p;

	buf = evhttp_request_get_input_buffer(req);

        p = evbuffer_pullup(buf, -1);

	if ((jmsg = json_loadb(p, evbuffer_get_length(buf), 0, &error)) == NULL) {
		fprintf(stdout, "%s: json_loadb - %s", __func__, error.text);
		goto err;
	}

	if (json_unpack(jmsg, "{s:s,s:s}", "cert", &cert, "cacert", &cacert)
	    < 0) {
		fprintf(stdout, "%s: json_unpack", __func__);
		goto err;
	}

	prov_info = arg;
	ndb_network_add(prov_info->network_name, prov_info->pvkey, cert,
	    cacert);

err:
	return;

}

int
agent_provisioning(const char *provkey, const char *network_name)
{
	EVP_PKEY			*keyring = NULL;
	X509_REQ			*certreq = NULL;
	digital_id_t			*nva_id = NULL;
	json_t				*jresp;
	struct evhttp_connection	*evhttp_conn;
	struct evhttp_request		*req;
	struct evkeyvalq		*output_headers;
	struct evbuffer			*output_buffer;
	struct prov_info		*prov_info;
	long				 size = 0;
	char				*resp;
	char				*certreq_pem = NULL;
	char				*pvkey_pem = NULL;

	nva_id = pki_digital_id("",  "", "", "", "contact@dynvpn.com", "www.dynvpn.com");

	/* generate RSA public and private keys */
	keyring = pki_generate_keyring();

	/* create a certificate signing request */
	certreq = pki_certificate_request(keyring, nva_id);

	/* write the certreq in PEM format */
	pki_write_certreq_in_mem(certreq, &certreq_pem, &size);

	/* write the private key in PEM format */
	pki_write_privatekey_in_mem(keyring, &pvkey_pem, &size);

	if ((prov_info = malloc(sizeof(struct prov_info))) == NULL)
		return (-1);

	prov_info->network_name = network_name;
	prov_info->pvkey = pvkey_pem;

	evhttp_conn = evhttp_connection_base_new(ev_base, NULL, "127.0.0.1", 8080);
	req = evhttp_request_new(http_prov_cb, prov_info);

	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Content-Type", "application/json");

        jresp = json_object();
        json_object_set_new(jresp, "csr", json_string(certreq_pem));

	json_object_set_new(jresp, "provkey", json_string(provkey));
        resp = json_dumps(jresp, 0);

	output_buffer = evhttp_request_get_output_buffer(req);
	evbuffer_add(output_buffer, resp, strlen(resp));

	evhttp_make_request(evhttp_conn, req, EVHTTP_REQ_POST, "/v1/provisioning");

	return (0);
}

int
agent_connect(const char *network_name)
{
	BIO			*bio = NULL;
	EC_KEY			*ecdh;
	struct timeval		timeout = {5, 0};
	struct event		*ev_udpclient;
	struct addrinfo	 	hints;
	struct dtls_peer	*p;
	int			 status;
	int			 flag;
	int			 ret;
	char			*pvkey;
	char			*cert;
	char			*cacert;
	const char		*ip = "127.0.0.1";
	const char		*port = "9090";

	printf("Connecting...\n");

	p = &switch_peer;
	p->state = DTLS_CONNECT;
	p->timer = evtimer_new(ev_base, dtls_peer_timeout_cb, p);

	if (ndb_network(network_name, &pvkey, &cert, &cacert) < 0) {
		fprintf(stderr, "The network specified doesn't exist: %s\n",
		    network_name);
		return (-1);
	}

	if ((passport = pki_passport_load_from_memory(cert, pvkey, cacert))
	    == NULL)
		err(1, "%s:%d", "pki_passport_load_from_memory", __LINE__);

	SSL_library_init();
	SSL_load_error_strings();

	if (!RAND_poll())
		err(1, "%s:%d", "RAND_poll", __LINE__);

	if ((ctx = SSL_CTX_new(DTLSv1_client_method())) == NULL)
		errx(1, "%s:%d", "SSL_CTX_new", __LINE__);

	SSL_CTX_set_read_ahead(ctx, 1);

	SSL_CTX_set_cert_store(ctx, passport->cacert_store);
	SSL_CTX_use_certificate(ctx, passport->certificate);
	SSL_CTX_use_PrivateKey(ctx, passport->keyring);

	if ((ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA")) == 0)
		err(1, "%s:%d", "SSL_CTX_set_cipher_list", __LINE__);

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		err(1, "%s:%d", "EC_KEY_new_by_curve_name", __LINE__);

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	EC_KEY_free(ecdh);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(ip, port, &hints, &ai)) != 0)
		errx(1, "%s:%s:%d", "getaddrinfo", gai_strerror(status), __LINE__);

	if ((p->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
		errx(1, "%s:%d", "socket", __LINE__);

	flag = 1;
	if (setsockopt(p->sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		errx(1, "%s:%d", "setsockopt", __LINE__);

	if (connect(p->sock, ai->ai_addr, ai->ai_addrlen) < 0)
		warn("%s:%d", "connect", __LINE__);

	if ((p->ssl = SSL_new(ctx)) == NULL)
		warnx("%s:%d", "SSL_new", __LINE__);

	SSL_set_tlsext_host_name(p->ssl, passport->nodeinfo->networkid);
	SSL_set_verify(p->ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);

	if ((bio = BIO_new_dgram(p->sock, BIO_NOCLOSE)) == NULL)
		warnx("%s:%d", "BIO_new_dgram", __LINE__);

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ai->ai_addr);

	SSL_set_bio(p->ssl, bio, bio);

	if (evutil_make_socket_nonblocking(p->sock) > 0)
		err(1, "%s:%d", "evutil_make_socket_nonblocking", __LINE__);

	SSL_set_connect_state(p->ssl);
	SSL_connect(p->ssl);

	if ((ev_udpclient = event_new(ev_base, p->sock,
	    EV_READ|EV_TIMEOUT|EV_PERSIST, udpclient_cb, p)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
	event_add(ev_udpclient, &timeout);

	return (0);
}

int
agent_init()
{
	struct event		*ev_iface;
	struct dtls_peer	*p;
	int			 iface_fd = 0;

	p = &switch_peer;

	if ((p->tapcfg = tapcfg_init()) == NULL) {
		fprintf(stderr, "tapcfg_init failed");
		return (-1);
	}

	if ((iface_fd = tapcfg_start(p->tapcfg, "netvirt0", 1)) < 0) {
		fprintf(stderr, "tapcfg_start\n");
		return (-1);
	}

	if ((ev_iface = event_new(ev_base, iface_fd,
	    EV_READ | EV_PERSIST, iface_cb, p)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
	event_add(ev_iface, NULL);

	return (0);	
}

void
agent_fini()
{

}

