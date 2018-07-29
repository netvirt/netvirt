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

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(__APPLE__)
	#include <pthread.h>
#endif

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <sys/socket.h>
	#include <netdb.h>
	#include <unistd.h>
#endif

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <event2/event.h>

#include <jansson.h>

#include <inet.h>
#include <pki.h>
#include <log.h>
#include <tapcfg.h>

#include "agent.h"

enum dtls_state {
	DTLS_CONNECT,
	DTLS_ESTABLISHED
};

struct dtls_conn {
	struct event	*ev_udpclient;
	struct event	*handshake_timer;
	struct event	*ping_timer;
	struct event	*ping_timeout;
	enum dtls_state	 state;
	SSL		*ssl;
	SSL_CTX		*ctx;
	int		 sock;
	int		 ping;
};

enum vlink_state {
	VSWITCH_DISCONNECTED,
	VSWITCH_CONNECTED
};

struct vlink {
	passport_t		*passport;
	tapcfg_t		*tapcfg;
	struct dtls_conn	*conn;
	int			 tapfd;
	char			*addr;
	enum vlink_state	 state;
};

struct eth_hdr {
	uint8_t		dmac[6];
	uint8_t		smac[6];
	uint16_t	ethertype;
} __attribute__((packed));

struct packets {
	int			 len;
	uint8_t			 buf[5000];
	TAILQ_ENTRY(packets)	 entries;
};

static struct addrinfo		*ai;
struct event_base		*ev_base;
struct eth_hdr			 eth_ping;
#if defined(_WIN32) || defined(__APPLE__)
pthread_t			 thread_poke_tap;
pthread_mutex_t			 mutex;
int				 switch_running = 0;
#endif
struct event			*ev_iface;

TAILQ_HEAD(tailhead, packets)	 tailq_head;

static int	 	 certverify_cb(int, X509_STORE_CTX *);
static void	 	 dtls_conn_free(struct dtls_conn *);
static struct dtls_conn	*dtls_conn_new(struct vlink *);
static void	 	 dtls_handshake_timeout_cb(int, short, void *);
static int	 	 dtls_handle(struct vlink *);
static void	 	 udpclient_cb(int, short, void *);

static void		 vlink_reconnect(struct vlink *);
static void	 	 iface_cb(int, short, void *);

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
ping_timeout_cb(int fd, short event, void *arg)
{
	(void)event;
	(void)fd;

	struct vlink	*vlink = arg;

	if (vlink->conn->ping > 3) {
		printf("not received > 3 keep alive\n");
		vlink_reconnect(vlink);
		return;
	}

	printf("send keep alive!\n");
	SSL_write(vlink->conn->ssl, (void *)&eth_ping, sizeof(struct eth_hdr));
	vlink->conn->ping++;
}

void
info_cb(const SSL *ssl, int where, int ret)
{
	(void)ret;

	struct vlink	*vlink;
	struct timeval	 timeout = {5, 0};

	if ((where & SSL_CB_HANDSHAKE_DONE) == 0)
		return;

	vlink = SSL_get_app_data(ssl);

	if (vlink->conn == NULL)
		return;

	vlink->conn->ping_timer = event_new(ev_base, -1, EV_TIMEOUT | EV_PERSIST,
	    ping_timeout_cb, (void *)vlink);
	event_add(vlink->conn->ping_timer, &timeout);

	// Reset the ev_udpclient event to remove the EV_TIMEOUT.
	evtimer_del(vlink->conn->ev_udpclient);
	event_assign(vlink->conn->ev_udpclient, ev_base, vlink->conn->sock,
	    EV_READ | EV_PERSIST, udpclient_cb, vlink);
	evtimer_add(vlink->conn->ev_udpclient, NULL);

	printf("connected !\n");
}

void
dtls_handshake_timeout_cb(int fd, short event, void *arg)
{
	(void)fd;
	(void)event;

	struct vlink	*vlink = arg;

	DTLSv1_handle_timeout(vlink->conn->ssl);

	if (dtls_handle(vlink) < 0) {
		vlink_reconnect(vlink);
	}
}

#if defined(_WIN32) || defined(__APPLE__)
void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	struct packets		 *pkt;
	struct vlink		 *vlink = arg;

	pthread_mutex_lock(&mutex);
	while ((pkt = TAILQ_FIRST(&tailq_head)) == NULL) {
		pthread_mutex_unlock(&mutex);
		return;
	}
	pthread_mutex_unlock(&mutex);

	if (vlink->conn != NULL && vlink->conn->state == DTLS_ESTABLISHED) {
		SSL_write(vlink->conn->ssl, pkt->buf, pkt->len);
		// XXX check ret
	}

	pthread_mutex_lock(&mutex);
	TAILQ_REMOVE(&tailq_head, pkt, entries);
	pthread_mutex_unlock(&mutex);
}

void *poke_tap(void *arg)
{
	struct vlink	*vlink = arg;
	struct packets	*pkt;

	if ((pkt = malloc(sizeof(struct packets))) == NULL) {
		log_warn("%s: malloc", __func__);
		return (NULL);
	}

	while (switch_running) {

		pkt->len = tapcfg_read(vlink->tapcfg, pkt->buf, sizeof(pkt->buf));
		// XXX check len

		pthread_mutex_lock(&mutex);
		TAILQ_INSERT_TAIL(&tailq_head, pkt, entries);
		pthread_mutex_unlock(&mutex);
		event_active(ev_iface, EV_TIMEOUT, 0);
	}

	return (NULL);
}
#else
void
iface_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;

	struct vlink	*vlink = arg;
	int			 ret;
	uint8_t			 buf[5000] = {0};

	vlink = arg;

	ret = tapcfg_read(vlink->tapcfg, buf, sizeof(buf));
	// XXX check ret

	if (vlink->conn != NULL && vlink->conn->state == DTLS_ESTABLISHED) {
		ret = SSL_write(vlink->conn->ssl, buf, ret);
		// XXX check ret
	}
}
#endif

int
dtls_handle(struct vlink *vlink)
{
	struct timeval	 tv;
	enum dtls_state	 next_state;
	unsigned long	 e;
	int		 ret;
	int		 line;
	char		 buf[5000] = {0};
	const char	*file;

	for (;;) {

		switch (vlink->conn->state) {
		case DTLS_CONNECT:
			ret = SSL_do_handshake(vlink->conn->ssl);
			next_state = DTLS_ESTABLISHED;
			break;

		case DTLS_ESTABLISHED:
			ret = SSL_read(vlink->conn->ssl, buf, sizeof(buf));
			// XXX check ret
			next_state = DTLS_ESTABLISHED;
			if (ret > 0) {

				if (inet_ethertype(buf) == ETHERTYPE_PING) {
					vlink->conn->ping = 0;
					return (0);
				}
				ret = tapcfg_write(vlink->tapcfg, buf, ret);
				// XXX check ret
				return (0);
			}
			break;

		default:
			fprintf(stderr, "%s: invalid DTLS peer state\n", __func__);
			return (-1);
		}

		switch (SSL_get_error(vlink->conn->ssl, ret)) {
		case SSL_ERROR_NONE:
			break;

		case SSL_ERROR_WANT_WRITE:
			return (0);

		case SSL_ERROR_WANT_READ:
			if (DTLSv1_get_timeout(vlink->conn->ssl, &tv) == 1 &&
			    evtimer_add(vlink->conn->handshake_timer, &tv) < 0) {
				return (-1);
			}
			return (0);
#ifdef _WIN32
		case SSL_ERROR_SYSCALL:
			/* An existing connection was forcibly closed by the remote host. */
			if (WSAGetLastError() != 10054)
				return (0);
			// fall to default
#endif
		default:
			fprintf(stderr, "%s: ssl error\n", __func__);

			do {
				e = ERR_get_error_line(&file, &line);
				printf("%s: %s", __func__, ERR_error_string(e, NULL));
			} while (e);

			return (-1);
		}

		vlink->conn->state = next_state;
	}

	return (0);
}

void
udpclient_cb(int sock, short what, void *arg)
{
	(void)sock;
	(void)what;
	(void)arg;

	struct vlink	*vlink = arg;

	printf("udpclient_cb\n");

	if (what & EV_TIMEOUT) {
		printf("sock timeout !\n");
		goto error;
	}

	if (dtls_handle(vlink) < 0) {
		printf("dtls handle failed\n");
		goto error;
	}

	return;

error:
	vlink_reconnect(vlink);
	return;
}

void
dtls_conn_free(struct dtls_conn *conn)
{
	if (conn == NULL)
		return;

	if (conn->ssl != NULL) {
		SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(conn->ssl);
		SSL_free(conn->ssl);
	}

	close(conn->sock);

	if (conn->ctx != NULL)
		SSL_CTX_free(conn->ctx);

	if (conn->handshake_timer != NULL)
		event_del(conn->handshake_timer);

	if (conn->ping_timer != NULL)
		event_del(conn->ping_timer);

	if (conn->ev_udpclient != NULL)
		evtimer_del(conn->ev_udpclient);

	free(conn);
}

struct dtls_conn *
dtls_conn_new(struct vlink *vlink)
{
	BIO			*bio = NULL;
	EC_KEY			*ecdh;
	struct timeval		timeout = {5, 0};
	struct addrinfo	 	hints;
	struct dtls_conn	*conn;
	unsigned long		 e;
	int			 ret;
	const char		*port = "9090";

	// XXX global init! 
	{
		SSL_library_init();
		SSL_load_error_strings();
		if (!RAND_poll())
			err(1, "%s: RAND_poll", __func__);
	}

	printf("Connecting to %s\n", vlink->addr);

	if ((conn = malloc(sizeof(struct dtls_conn))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto cleanup;
	}
	conn->handshake_timer = NULL;
	conn->ping_timer = NULL;
	conn->state = DTLS_CONNECT;
	conn->ssl = NULL;
	conn->ping = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if ((ret = getaddrinfo(vlink->addr, port, &hints, &ai)) < 0) {
		log_warnx("%s: getaddrinfo %s", __func__, gai_strerror(ret));
		goto cleanup;
	}

	if ((conn->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
		log_warnx("%s: socket", __func__);
		goto cleanup;
	}

#ifndef _WIN32
	int flag = 1;
	if (setsockopt(conn->sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
		log_warn("%s: setsockopt", __func__);
		goto cleanup;
	}
#endif

	if (evutil_make_socket_nonblocking(conn->sock) > 0) {
		log_warnx("%s: evutil_make_socket_nonblocking", __func__);
		goto cleanup;
	}

	if (connect(conn->sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		log_warn("%s: connect", __func__);
		goto cleanup;
	}

	if ((conn->ctx = SSL_CTX_new(DTLSv1_client_method())) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		while ((e = ERR_get_error()))
			log_warnx("%s", ERR_error_string(e, NULL));
		goto cleanup;
	}

	if (SSL_CTX_set_cipher_list(conn->ctx, "ECDHE-ECDSA-AES256-SHA") != 1) {
		log_warnx("%s: SSL_CTX_set_cipher_list", __func__);
		while ((e = ERR_get_error()))
			log_warnx("%s", ERR_error_string(e, NULL));
		goto cleanup;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("%s: EC_KEY_new_by_curve_name", __func__);
		goto cleanup;
	}
	SSL_CTX_set_tmp_ecdh(conn->ctx, ecdh);
	EC_KEY_free(ecdh);


	SSL_CTX_set_cert_store(conn->ctx, vlink->passport->cacert_store);
	X509_STORE_up_ref(vlink->passport->cacert_store);

	if ((SSL_CTX_use_certificate(conn->ctx, vlink->passport->certificate)) != 1) {
		log_warnx("%s: SSL_CTX_use_certificate", __func__);
		goto cleanup;
	}
	if ((SSL_CTX_use_PrivateKey(conn->ctx, vlink->passport->keyring)) != 1) {
		log_warnx("%s: SSL_CTX_use_PrivateKey", __func__);
		goto cleanup;
	}

	SSL_CTX_set_read_ahead(conn->ctx, 1);

	if ((conn->ssl = SSL_new(conn->ctx)) == NULL) {
		log_warnx("%s: SSL_new", __func__);
		goto cleanup;
	}

	if (SSL_set_app_data(conn->ssl, vlink) != 1) {
		log_warnx("%s: SSL_set_app_data", __func__);
		goto cleanup;
	}

	SSL_set_info_callback(conn->ssl, info_cb);
	SSL_set_tlsext_host_name(conn->ssl, vlink->passport->certinfo->network_uid);
	SSL_set_verify(conn->ssl,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, certverify_cb);

	if ((bio = BIO_new_dgram(conn->sock, BIO_NOCLOSE)) == NULL) {
		log_warnx("%s: BIO_new_dgram", __func__);
		goto cleanup;
	}

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ai->ai_addr);

	SSL_set_bio(conn->ssl, bio, bio);

	SSL_set_connect_state(conn->ssl);

	if ((conn->ev_udpclient = event_new(ev_base, conn->sock,
	    EV_READ|EV_PERSIST, udpclient_cb, vlink)) == NULL) {
		log_warnx("%s: event_new", __func__);
		goto cleanup;
	}
	event_add(conn->ev_udpclient, &timeout);

	if ((conn->handshake_timer = evtimer_new(ev_base, dtls_handshake_timeout_cb, vlink)) == NULL) {
		log_warnx("%s: evtimer_new", __func__);
		goto cleanup;
	}

	SSL_connect(conn->ssl);

	return (conn);

cleanup:

	vlink_reconnect(vlink);
	return (NULL);
}

void
vlink_connstart(evutil_socket_t fd, short what, void *arg)
{
	struct vlink	*vlink = arg;
	(void)fd;
	(void)what;

	if (vlink->conn != NULL) {
		dtls_conn_free(vlink->conn);
		vlink->conn = NULL;
	}

	if ((vlink->conn = dtls_conn_new(vlink)) == NULL) {
		log_warnx("%s: dtls_conn_new", __func__);
		goto error;
	}

	return;

error:
	vlink_reconnect(vlink);

	return;
}

void
vlink_reconnect(struct vlink *vlink)
{
	struct timeval	one_sec = {5, 0};

	vlink->state = VSWITCH_DISCONNECTED;

	// Disable timeout on the UDP socket to prevent calling reconnect again.
	if (vlink->conn != NULL && vlink->conn->ev_udpclient != NULL)
		evtimer_del(vlink->conn->ev_udpclient);

	if (vlink->conn != NULL && vlink->conn->ping_timer != NULL)
		event_del(vlink->conn->ping_timer);


	if (event_base_once(ev_base, -1, EV_TIMEOUT,
	    vlink_connstart, vlink, &one_sec) < 0)
		log_warnx("%s: event_base_once", __func__);
}

int
switch_init(tapcfg_t *tapcfg, int tapfd, const char *vswitch_addr, const char *ipaddr,
    const char *network_name)
{
	struct network	*netcf = NULL;
	struct vlink	*vlink = NULL;

	eth_ping.ethertype = htons(0x9000);

	if ((vlink = malloc(sizeof(struct vlink))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto cleanup;
	}
	vlink->passport = NULL;
	vlink->tapcfg = NULL;
	vlink->conn = NULL;
	vlink->addr = NULL;

	vlink->tapcfg = tapcfg;
	vlink->tapfd = tapfd;

	if ((vlink->addr = strdup(vswitch_addr)) == NULL) {
		log_warn("%s: strdup", __func__);
		goto cleanup;
	}

	tapcfg_iface_set_status(tapcfg, TAPCFG_STATUS_IPV4_UP);
	// XXX netmask not always 24
	tapcfg_iface_set_ipv4(tapcfg, ipaddr, 24);

	if ((netcf = ndb_network(network_name)) == NULL) {
		log_warnx("%s: the network doesn't exist: %s",
		    __func__, network_name);
		goto cleanup;
	}

	if ((vlink->passport =
	    pki_passport_load_from_memory(netcf->cert, netcf->pvkey, netcf->cacert)) == NULL) {
		log_warnx("%s: pki_passport_load_from_memory", __func__);
		goto cleanup;
	}

#if defined(_WIN32) || defined(__APPLE__)
	TAILQ_INIT(&tailq_head);

	switch_running = 1;

	pthread_attr_t	attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_poke_tap, &attr, poke_tap, vlink);

	if ((ev_iface = event_new(ev_base, 0,
		EV_TIMEOUT, iface_cb, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
#else
	if ((ev_iface = event_new(ev_base, tapfd,
	    EV_READ | EV_PERSIST, iface_cb, vlink)) == NULL)
		warn("%s:%d", "event_new", __LINE__);
#endif
	event_add(ev_iface, NULL);

	vlink_reconnect(vlink);

	return (0);

cleanup:

	return (-1);
}

void
switch_fini(void)
{
#if defined(_WIN32) || defined(__APPLE__)
	switch_running = 0;
	pthread_join(thread_poke_tap, NULL);
#endif
}
