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

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <syslog-compat.h>
#else
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <sys/socket.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <syslog.h>
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <jansson.h>

#include <pki.h>
#include <log.h>
#include <tapcfg.h>

#include "agent.h"

struct tls_conn {
	struct bufferevent	*bev;
	SSL			*ssl;
	SSL_CTX			*ctx;
	struct tapif		*tapif;
};

struct ctlinfo {
	struct tls_conn	*conn;
	char		*srv_addr;
	char		*srv_port;
	tapcfg_t	*tapcfg;
	int		 tapfd;
	char		*netname;
	passport_t	*passport;
};

static struct tls_conn	*tls_conn_new(struct ctlinfo *);
static void		 tls_conn_free(struct tls_conn *);
static struct ctlinfo	*ctlinfo_new();
static void		 ctlinfo_free(struct ctlinfo *);
static void		 control_reconnect(struct ctlinfo *);

#ifdef _WIN32
const char *
inet_ntop(int af, const void* src, char* dst, int cnt)
{
	struct sockaddr_in	srcaddr;

	memset(&srcaddr, 0, sizeof(struct sockaddr_in));
	memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));
	srcaddr.sin_family = af;

	if (WSAAddressToString((struct sockaddr*) &srcaddr,
	    sizeof(struct sockaddr_in), 0, dst, (LPDWORD) &cnt) != 0) {
		WSAGetLastError();
		return (NULL);
	}

	return (dst);
}

int
inet_pton(int af, const char *src, void *dst)
{
	struct sockaddr_storage	ss;
	int			size;
	char			src_tmp[INET_ADDRSTRLEN+1];

	size = sizeof(ss);

	ZeroMemory(&ss, sizeof(ss));
	strncpy (src_tmp, src, INET_ADDRSTRLEN+1);
	src_tmp[INET_ADDRSTRLEN] = 0;

	if (WSAStringToAddress(src_tmp, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
		switch(af) {
		case AF_INET:
			*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
			return (1);
		}
	}

	return (0);
}
#endif

char *
local_ipaddr()
{
#ifdef _WIN32
	WORD	wVersionRequested = MAKEWORD(1,1);
	WSADATA wsaData;
#endif
	struct addrinfo		*serv_info;
	struct sockaddr_in	 name;
	int			 sock;
	const char		*addr_ptr;
	char			*listen_addr = "dynvpn.com";
	char			*port = "9092";
	char			 local_ip[16];

#ifdef _WIN32
	/* init Winsocket */
	WSAStartup(wVersionRequested, &wsaData);
#endif
	// XXX handler errors
	sock = socket(AF_INET, SOCK_DGRAM, 0);

	getaddrinfo(listen_addr, port, NULL, &serv_info);
	connect(sock, serv_info->ai_addr, serv_info->ai_addrlen);
	freeaddrinfo(serv_info);

	socklen_t namelen = sizeof(name);
	getsockname(sock, (struct sockaddr *)&name, &namelen);

#ifdef _WIN32
	closesocket(sock);
	WSACleanup();
#else
	close(sock);
#endif

	if ((addr_ptr = inet_ntop(AF_INET, &name.sin_addr, local_ip,
	 INET_ADDRSTRLEN)) == NULL)
		return (NULL);

	return (strdup(local_ip));
}

int
xmit_nodeinfo(struct ctlinfo *ctl)
{
	json_t		*jmsg = NULL;
	int		 ret;
	int		 lladdr_len;
	const char	*lladdr;
	char		 lladdr_str[18];
	char		*lipaddr = NULL;
	char		*msg = NULL;

	ret = -1;

	if ((lladdr = tapcfg_iface_get_hwaddr(ctl->tapcfg, &lladdr_len))
	    == NULL) {
		log_warnx("%s: tapcfg_iface_get_hwaddr", __func__);
		goto error;
	}

	if ((lipaddr = local_ipaddr()) == NULL) {
		log_warnx("%s: local_ipaddr", __func__);
		goto error;
	}

	snprintf(lladdr_str, sizeof(lladdr_str),
	    "%02x:%02x:%02x:%02x:%02x:%02x",
            ((uint8_t *)lladdr)[0],
            ((uint8_t *)lladdr)[1],
            ((uint8_t *)lladdr)[2],
            ((uint8_t *)lladdr)[3],
            ((uint8_t *)lladdr)[4],
            ((uint8_t *)lladdr)[5]);

	if ((jmsg = json_pack("{s:s,s:s,s:s}",
	    "action", "nodeinfo",
	    "local_ipaddr", lipaddr,
	    "lladdr", lladdr_str)) == NULL) {
		log_warnx("%s: json_pack", __func__);
		goto error;
	}

	if ((msg = json_dumps(jmsg, 0)) == NULL) {
		log_warnx("%s: json_dumps", __func__);
		goto error;
	}

	// XXX use buffer and then one write
	if (bufferevent_write(ctl->conn->bev, msg, strlen(msg)) != 0) {
		log_warnx("%s: bufferevent_write", __func__);
		goto error;
	}

	if (bufferevent_write(ctl->conn->bev, "\n", strlen("\n")) != 0) {
		log_warnx("%s: bufferevent_write", __func__);
		goto error;
	}

	ret = 0;

error:
	json_decref(jmsg);
	free(msg);
	free(lipaddr);

	return (ret);
}

void
client_onread_cb(struct bufferevent *bev, void *arg)
{
	json_error_t		 error;
	json_t			*jmsg = NULL;
	struct ctlinfo		*ctl = arg;
	size_t			 n_read_out;
	const char		*action;
	const char		*ipaddr;
	const char		*vswitch_addr;
	char			*msg = NULL;

	while (evbuffer_get_length(bufferevent_get_input(bev)) > 0) {

		if ((msg = evbuffer_readln(bufferevent_get_input(bev),
		    &n_read_out, EVBUFFER_EOL_LF)) == NULL) {
			/* XXX timeout timer */
			return;
		}

		if ((jmsg = json_loadb(msg, n_read_out, 0, &error)) == NULL) {
			log_warnx("%s: json_loadb", __func__);
			goto error;
		}

		if (json_unpack(jmsg, "{s:s}", "action", &action) < 0) {
			log_warnx("%s: json_unpack action", __func__);
			goto error;
		}

		if (strcmp(action, "networkinfo") == 0) {

			if (json_unpack(jmsg, "{s:s, s:s}", "vswitch_addr", &vswitch_addr, "ipaddr", &ipaddr)
			    < 0) {
				log_warnx("%s: json_unpack ipaddr", __func__);
				goto error;
			}

			switch_init(ctl->tapcfg, ctl->tapfd, vswitch_addr, ipaddr, ctl->netname);
		}
	}

	json_decref(jmsg);
	free(msg);

	return;

error:
	json_decref(jmsg);
	free(msg);
	control_reconnect(ctl);

	return;
}

void
client_onevent_cb(struct bufferevent *bev, short events, void *arg)
{
	struct ctlinfo	*ctl = arg;
	unsigned long	 e;

	if (events & BEV_EVENT_CONNECTED) {

		printf("event connected\n");

		if (xmit_nodeinfo(ctl) < 0)
			goto error;

	} else if (events & (BEV_EVENT_TIMEOUT | BEV_EVENT_EOF)) {

		printf("timeout | EOF\n");

		goto error;

	} else if (events &  BEV_EVENT_ERROR) {

		printf("error: %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

		while ((e = bufferevent_get_openssl_error(bev)) > 0) {
			log_warnx("%s: TLS error: %s", __func__,
			    ERR_reason_error_string(e));
		}

		goto error;
	}

	return;

error:
	control_reconnect(ctl);

	return;
}

struct ctlinfo *
ctlinfo_new()
{
	struct ctlinfo	*ctl = NULL;

	if ((ctl = malloc(sizeof(*ctl))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto error;
	}
	ctl->conn = NULL;
	ctl->tapcfg = NULL;
	ctl->netname = NULL;
	ctl->passport = NULL;
	ctl->srv_addr = NULL;
	ctl->srv_port = NULL;

	return (ctl);

error:
	ctlinfo_free(ctl);

	return (NULL);
}

void
ctlinfo_free(struct ctlinfo *ctl)
{
	if (ctl == NULL)
		return;

	pki_passport_destroy(ctl->passport);
	tls_conn_free(ctl->conn);
	tapcfg_destroy(ctl->tapcfg);

	free(ctl->srv_addr);
	free(ctl->srv_port);
	free(ctl->netname);
	free(ctl);

	return;
}

struct tls_conn *
tls_conn_new(struct ctlinfo *ctl)
{
	struct tls_conn		*conn = NULL;
	struct addrinfo		*res = NULL;
	struct addrinfo		 hints;
	EC_KEY			*ecdh = NULL;
	unsigned long		 e;
	int			 fd = -1;
	int			 flag;
	int			 ret;

	if ((conn = malloc(sizeof(struct tls_conn))) == NULL) {
		log_warn("%s: malloc", __func__);
		goto cleanup;
	}
	conn->ssl = NULL;
	conn->ctx = NULL;
	conn->bev = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo(ctl->srv_addr, ctl->srv_port, &hints, &res)) < 0) {
		log_warnx("%s: getaddrinfo %s", __func__, gai_strerror(ret));
		goto cleanup;
	}

	if ((fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_warnx("%s: socket", __func__);
		goto cleanup;
	}

#ifndef WIN32
	flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0 ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
		log_warn("%s: setsockopt", __func__);
		goto cleanup;
	}
#endif

	if (evutil_make_socket_nonblocking(fd) < 0) {
		log_warnx("%s: evutil_make_socket_nonblocking", __func__);
		goto cleanup;
	}

	if ((conn->ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
		log_warnx("%s: SSL_CTX_new", __func__);
		while ((e = ERR_get_error()))
			log_warnx("%s", ERR_error_string(e, NULL));

		goto cleanup;
	}

	if (SSL_CTX_set_cipher_list(conn->ctx,
	    "ECDHE-ECDSA-CHACHA20-POLY1305,"
	    "ECDHE-ECDSA-AES256-GCM-SHA384") != 1) {
		log_warnx("%s: SSL_CTX_set_cipher", __func__);
		while ((e = ERR_get_error()))
			log_warnx("%s", ERR_error_string(e, NULL));
		goto cleanup;
	}

	if ((ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		log_warnx("%s: EC_KEY_new_by_curve", __func__);
		goto cleanup;
	}

	SSL_CTX_set_cert_store(conn->ctx, ctl->passport->cacert_store);
	X509_STORE_up_ref(ctl->passport->cacert_store);

	if ((SSL_CTX_use_certificate(conn->ctx, ctl->passport->certificate)) != 1) {
		log_warnx("%s: SSL_CTX_use_certificate", __func__);
		goto cleanup;
	}

	if ((SSL_CTX_use_PrivateKey(conn->ctx, ctl->passport->keyring)) != 1) {
		log_warnx("%s: SSL_CTX_use_PrivateKey", __func__);
		goto cleanup;
	}

	if ((conn->ssl = SSL_new(conn->ctx)) == NULL) {
		log_warnx("%s: SSL_new", __func__);
		goto cleanup;
	}

	SSL_set_tlsext_host_name(conn->ssl, ctl->passport->certinfo->network_uid);

	if ((conn->bev = bufferevent_openssl_socket_new(ev_base, fd, conn->ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS)) == NULL) {
		log_warnx("%s: bufferevent_openssl_socket_new", __func__);
		goto cleanup;
	}

	bufferevent_setcb(conn->bev,
	    client_onread_cb, NULL, client_onevent_cb, ctl);
	bufferevent_enable(conn->bev, EV_READ | EV_WRITE);

	if (bufferevent_socket_connect(conn->bev, res->ai_addr, res->ai_addrlen)
	    < 0) {
		log_warnx("%s: bufferevent_socket_connected", __func__);
		goto cleanup;
	}

	EC_KEY_free(ecdh);
	freeaddrinfo(res);

	return (conn);

cleanup:
	EC_KEY_free(ecdh);
	tls_conn_free(conn);
	freeaddrinfo(res);
	close(fd);

	return (NULL);
}

void
tls_conn_free(struct tls_conn *conn)
{
	if (conn == NULL)
		return;

	if (conn->ssl != NULL) {
		SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(conn->ssl);
	}

	if (conn->bev != NULL)
		bufferevent_free(conn->bev);

	if (conn->ctx != NULL)
		SSL_CTX_free(conn->ctx);

	free(conn);

	return;
}

void
control_connstart(evutil_socket_t fd, short what, void *arg)
{
	struct ctlinfo	*ctl = arg;
	(void)fd;
	(void)what;

	if (ctl->conn != NULL) {
		tls_conn_free(ctl->conn);
		ctl->conn = NULL;
	}

	if ((ctl->conn = tls_conn_new(ctl)) == NULL) {
		log_warnx("%s: tls_conn_new", __func__);
		goto error;
	}

	return;

error:
	control_reconnect(ctl);

	return;
}

void
control_reconnect(struct ctlinfo *ctl)
{
	struct timeval	one_sec = {1, 0};

	if (ctl->conn != NULL && ctl->conn->bev != NULL) {
		bufferevent_disable(ctl->conn->bev, EV_READ | EV_WRITE);
	}

	if (event_base_once(ev_base, -1, EV_TIMEOUT,
	    control_connstart, ctl, &one_sec) < 0)
		log_warnx("%s: event_base_once", __func__);
}

// XXX need a ctlinfo list
struct ctlinfo		*ctl = NULL;

int
control_init(const char *network_name)
{
	struct network		*netcf = NULL;

	// XXX init globally
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	log_init(2, LOG_DAEMON);

	printf("network name: %s\n", network_name);

	if ((netcf = ndb_network(network_name)) == NULL) {
		log_warnx("%s: the network doesn't exist: %s",
		    __func__, network_name);
		goto error;
	}

	if ((ctl = ctlinfo_new()) == NULL) {
		log_warnx("%s: ctlinfo_new", __func__);
		goto error;
	}

	if ((ctl->tapcfg = tapcfg_init()) == NULL) {
		log_warnx("%s: tapcfg_init", __func__);
		goto error;
	}

	if ((ctl->tapfd = tapcfg_start(ctl->tapcfg, "netvirt0", 1)) < 0) {
		log_warnx("%s: tapcfg_start", __func__);
	}

	if ((ctl->netname = strdup(network_name)) == NULL) {
		log_warn("%s: strdup", __func__);
		goto error;
	}

	if ((ctl->srv_addr = strdup(netcf->ctlsrv_addr)) == NULL) {
		log_warn("%s: strdup", __func__);
		goto error;
	}

	if ((ctl->srv_port = strdup("7032")) == NULL) {
		log_warn("%s: strdup", __func__);
		goto error;
	}

	if ((ctl->passport =
	    pki_passport_load_from_memory(netcf->cert, netcf->pvkey, netcf->cacert)) == NULL) {
		log_warnx("%s: pki_passport_load_from_memory", __func__);
		goto error;
	}

	control_reconnect(ctl);

	return (0);

error:
	return (-1);
}

void
control_fini(void)
{
	ctlinfo_free(ctl);
}
