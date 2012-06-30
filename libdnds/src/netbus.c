/*
 * netbus.c: Low level network API
 *
 * Copyright (C) Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define __USE_BSD
#define __favor_BSD

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "ion.h"
#include "journal.h"
#include "netbus.h"
#include "tun.h"
#include "udtbus.h"
#include "xsched.h"

#define CONN_BACKLOG 512
#define INVALID_Q -1

int netbus_queue = INVALID_Q;

#define NETBUS_TCP_SERVER	0x1
#define NETBUS_TCP_CLIENT	0x2
#define NETBUS_ICMP_PING	0x3

/* TODO
 * put all iface related code in another subsystem
 */

static int setnonblocking(int socket)
{
	int ret;
	ret = fcntl(socket, F_GETFL);
	if (ret >= 0) {
		ret = fcntl(socket, F_SETFL, ret | O_NONBLOCK);
	}
	return ret;
}

static int setreuse(int socket)
{
	int ret, on = 1;
	ret = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
	return ret;
}

/* Directly stolen from OpenBSD{ping.c} */
static unsigned short chksum(u_short *addr, int len)
{
        int nleft = len;
        u_short *w = addr;
        int sum = 0;
        u_short answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

static int netbus_ping(peer_t *peer)
{
	int ret;
	size_t len;

	struct sockaddr_in dst_addr;
	char icmp_packet[sizeof(struct ip) + sizeof(struct icmp)];

	memset(icmp_packet, 0, sizeof(struct ip) + sizeof(struct icmp));
	memset(&dst_addr, 0, sizeof(struct sockaddr_in));

	struct ip *iphdr = (struct ip *)icmp_packet;
	struct icmp *icmphdr = (struct icmp *)(icmp_packet + sizeof(struct ip));

	/* build IP header */
	iphdr->ip_v = IPVERSION;
	iphdr->ip_hl = sizeof(struct ip) >> 2;
	iphdr->ip_tos = 0; /* 0 means kernel set appropriate value */
	iphdr->ip_id = 0;
	iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp));
	iphdr->ip_ttl = 2;
	iphdr->ip_p = IPPROTO_ICMP;
	iphdr->ip_sum = 0;
	iphdr->ip_src.s_addr = INADDR_ANY;
	iphdr->ip_dst.s_addr = peer->dst.s_addr;

	/* build ICMP header */
	icmphdr->icmp_type = ICMP_ECHO;
	icmphdr->icmp_code = 0;
	icmphdr->icmp_cksum = 0;

	/* We use the socket descriptor id/process id as a seq/id number.
	 * cheapest way to track icmp-reply.
	 */
	icmphdr->icmp_seq = getpid();
	icmphdr->icmp_id = peer->socket;

	icmphdr->icmp_cksum = chksum((unsigned short *)icmphdr, sizeof(struct icmp));
	iphdr->ip_sum = chksum((unsigned short *)iphdr, sizeof(struct ip));

	dst_addr.sin_addr.s_addr = peer->dst.s_addr;
	len = sizeof(struct ip) + sizeof(struct icmp);
	ret = sendto(peer->socket, icmp_packet, len, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr));
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> netbus_ping() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

static void catch_pingreply(peer_t *peer)
{
	int ret = 0;
	socklen_t addrlen = 0;
	struct ip *ip_reply = NULL;
	struct icmp *icmp_reply = NULL;

	struct sockaddr_in saddr;

	fd_set rfds;
	struct timeval tv;

	static char buffer[sizeof(struct ip) + sizeof(struct icmp)];
	memset(buffer, 0, sizeof(buffer));

	addrlen = (socklen_t)sizeof(struct sockaddr_in);
	ret = recvfrom(peer->socket, buffer, sizeof(struct ip) + sizeof(struct icmp), 0,
		(struct sockaddr*)&saddr, &addrlen);

	ip_reply = (struct ip*)buffer;
	icmp_reply = (struct icmp*)(buffer + sizeof(struct ip));

	/*
	 * does this echo-reply belongs to this socket ?
	 */
	if (icmp_reply->icmp_id == peer->socket &&
		icmp_reply->icmp_seq == getpid() &&
		icmp_reply->icmp_type == 0) { // ECHO-REPLY

		if (peer->on_pingreply)
			peer->on_pingreply(peer);

		jlog(L_DEBUG, "ping]> ID: %d", ntohs(ip_reply->ip_id));
		jlog(L_DEBUG, "ping]> TTL: %d", ip_reply->ip_ttl);
		jlog(L_DEBUG, "ping]> Received %d byte reply from %s:",
			sizeof(buffer), inet_ntoa(ip_reply->ip_src));

		jlog(L_DEBUG, "ping]> type: %i", icmp_reply->icmp_type);
		jlog(L_DEBUG, "ping]> code: %i", icmp_reply->icmp_code);
		jlog(L_DEBUG, "ping]> id  : %i", icmp_reply->icmp_id);
		jlog(L_DEBUG, "ping]> seq : %i", icmp_reply->icmp_seq);
	}
}

static int netbus_write(iface_t *iface, void *frame, int sz)
{
	int ret;
	ret = write(iface->fd, frame, sz);

	return ret;
}

static int netbus_read(iface_t *iface)
{
// TODO use dynamic buffer
#define IFACE_BUF_SZ 5000
	int ret = 0;

	if (iface->frame == NULL) {
		iface->frame = calloc(1, IFACE_BUF_SZ);
		if (iface->frame == NULL) {
			jlog(L_NOTICE, "netbus]> netbus_read() calloc FAILED :: %s:%i", __FILE__, __LINE__);
			return -1;
		}
	}
	else
		memset(iface->frame, 0, IFACE_BUF_SZ);

	ret = read(iface->fd, iface->frame, IFACE_BUF_SZ);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> netbus_read() failed %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		return -1;
	}

	return ret;
}

static int netbus_send(peer_t *peer, void *data, int len)
{
	int ret = 0;
	int total = 0;
	int byteleft = len;

	errno = 0;
	while (total < len) {
		ret = send(peer->socket, (uint8_t*)data + total, byteleft, 0);

		if (errno != 0)
			jlog(L_ERROR, "netbus]> netbus_send errno [%i] :: %s:%i", __FILE__, __LINE__);

		if (ret == -1 && errno != 11)
			return -1;

		if (ret != -1) {
			total += ret;
			byteleft -= ret;
		}
	}
	return ret;
}

static int netbus_recv(peer_t *peer)
{
// TODO use dynamic buffer
#define PEER_BUF_SZ 5000
	fd_set rfds;
	struct timeval tv;
	int ret = 0;
	char tmpbuf[5000];

	FD_ZERO(&rfds);
	FD_SET(peer->socket, &rfds);

	/* Wait up to five seconds */
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	ret = select(peer->socket + 1, &rfds, NULL, NULL, &tv);
	if (ret == 0) { /* TIMEOUT !*/
		jlog(L_NOTICE, "netbus]> netbus_recv() TIMEOUT peer->socket(%i) :: %s:%i",
			peer->socket, __FILE__, __LINE__);
		return -1;
	}

	if (peer->buffer == NULL) {
		peer->buffer = calloc(1, PEER_BUF_SZ);
		if (peer->buffer == NULL) {
			jlog(L_ERROR, "netbus]> netbus_recv() calloc FAILED :: %s:%i", __FILE__, __LINE__);
			return -1;
		}
	}
	else {
		memset(peer->buffer, 0, PEER_BUF_SZ);
	}

	/*
	 * XXX It may happen that the buffer is too short,
	 * in that case we should then re-alloc and move
	 * the bytes.
	 */
	ret = recv(peer->socket, peer->buffer, PEER_BUF_SZ, 0);

	if (ret < 0)
		return -1;

	return ret;
}

static void netbus_shutdown(iface_t *iface)
{
	int ret;
	ret = close(iface->fd);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> iface closed: %u %u %s :: %s:%i",
			iface->fd, ret, strerror(errno), __FILE__, __LINE__);
		return;
	}

	free(iface->frame);
	free(iface);
}

static void notify_input_frame(iface_t *iface)
{
//	jlog(L_DEBUG, "netbus]> received frame from iface {%s}", iface->devname);

	if (iface->on_input)
		iface->on_input(iface);
}

static void netbus_disconnect(peer_t *peer)
{
	int ret;

	//close() will cause the socket to be automatically removed from the queue
	ret = close(peer->socket);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> close() failed: %u %u %s :: %s:%i",
			peer->socket, ret, strerror(errno), __FILE__, __LINE__);
		return;
	}

	jlog(L_DEBUG, "netbus]> client close: %u", peer->socket);

	free(peer->buffer);
	free(peer);
}

static void on_disconnect(peer_t *peer)
{
	// inform upper layer
	if (peer->on_disconnect)
		peer->on_disconnect(peer);

	netbus_disconnect(peer);
}

static void on_input(peer_t *peer)
{
	jlog(L_DEBUG, "netbus]> received data for peer {%i}", peer->socket);

	if (peer->on_input)
		peer->on_input(peer);
}

static void on_connect(peer_t *peer)
{
	int ret, addrlen;
	struct sockaddr_in addr;
	struct netbus_sys *nsys;
	peer_t *npeer;

	nsys = calloc(sizeof(struct netbus_sys), 1);
	npeer = calloc(sizeof(peer_t), 1);

	if (!nsys || !npeer)
		return;

	addrlen = sizeof(struct sockaddr_in);
	npeer->socket = accept(peer->socket, (struct sockaddr *)&addr, (socklen_t *)&addrlen);
	if (npeer->socket < 0) {
		jlog(L_ERROR, "netbus]> accept() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		free(npeer);
		return;
	}

	ret = setnonblocking(npeer->socket);
        if (ret < 0) {
                jlog(L_ERROR, "netbus]> setnonblocking() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		free(npeer);
                return;
        }

	// XXX need an init func ?
	npeer->type = NETBUS_TCP_CLIENT;
	npeer->on_connect = peer->on_connect;
	npeer->on_disconnect = peer->on_disconnect;
	npeer->on_input = peer->on_input;
	npeer->recv = peer->recv;
	npeer->send = peer->send;
	npeer->disconnect = peer->disconnect;
	npeer->ext_ptr = peer->ext_ptr;
	npeer->buffer = NULL;

	nsys->type = NETBUS_PEER;
	nsys->peer = npeer;
	ret = ion_add(netbus_queue, npeer->socket, nsys);
	if (ret < 0) {
		jlog(L_ERROR, "netbus]> ion_add() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		free(npeer);
	}

	if (peer->on_connect)
		peer->on_connect(npeer);

	jlog(L_DEBUG, "netbus]> successfully added TCP client {%i} on server {%i}", npeer->socket, peer->socket);
}

// Handle IO Events
static void netbus_hioe(void *udata, int flag)
{
	struct netbus_sys *nsys;
	nsys = udata;

	if (nsys->type == NETBUS_PEER) {
		if (flag == ION_EROR) {
			on_disconnect(nsys->peer);
		}
		else if (flag == ION_READ) {
			// TCP
			if (nsys->peer->type == NETBUS_TCP_SERVER) {
				on_connect(nsys->peer);
			}

			if (nsys->peer->type == NETBUS_TCP_CLIENT) {
				on_input(nsys->peer);
			}

			// PING
			if (nsys->peer->type == NETBUS_ICMP_PING) {
				catch_pingreply(nsys->peer);
			}
		}
	}
	else if (nsys->type == NETBUS_IFACE) {
		if (flag == ION_EROR) {
			netbus_shutdown(nsys->iface);
		}
		else if (flag == ION_READ) {
			notify_input_frame(nsys->iface);
		}
	}
}

static void poke_queue(void *udata)
{
	int ret;

	ret = ion_poke(netbus_queue, netbus_hioe);
	if (ret < 0) {
		jlog(L_DEBUG, "netbus]> ion_poke() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		return;
	}
}

iface_t *netbus_newtun(void (*on_input)(iface_t *))
{
	int ret;

	struct netbus_sys *nsys;
	iface_t *iface;

	if (netbus_queue == INVALID_Q) {
		jlog(L_ERROR, "netbus]> subsystem unitialized :: %s:%i", __FILE__, __LINE__);
		return NULL;
	}

	nsys = calloc(sizeof(struct netbus_sys), 1);
	iface = calloc(sizeof(iface_t), 1);

	if (!nsys || !iface)
		return NULL;

	ret = tun_create((char*)&(iface->devname), &(iface->fd));
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> tun_create failed %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		free(iface);
		free(nsys);
		return NULL;
	}

	ret = setnonblocking(iface->fd);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> setnonblocking() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		tun_destroy(iface);
		close(iface->fd);
		free(iface);
		free(nsys);
		return NULL;
	}

	iface->on_input = on_input;
	iface->write = netbus_write;
	iface->read = netbus_read;
	iface->shutdown = netbus_shutdown;
	iface->frame = NULL;

	nsys->type = NETBUS_IFACE;
	nsys->iface = iface;

	ret = ion_add(netbus_queue, iface->fd, nsys);
	if (ret < 0) {
		jlog(L_NOTICE, "ion_add() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		tun_destroy(iface);
		close(iface->fd);
		free(iface);
		free(nsys);
		return NULL;
	}

	return iface;
}

peer_t *netbus_tcp_client(const char *addr,
			  const int port,
			  void (*on_disconnect)(peer_t*),
			  void (*on_input)(peer_t*))
{
	fd_set wfds;
	struct timeval tv;
	int ret = 0;
	int optval = 0;
	socklen_t optlen = 0;
	struct sockaddr_in addr_in;
	struct netbus_sys *nsys = NULL;
	peer_t *peer = NULL;

	FD_ZERO(&wfds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	if (netbus_queue == INVALID_Q) {
		jlog(L_ERROR, "netbus]> subsystem unitialized :: %s:%i", __FILE__, __LINE__);
		return NULL;
	}

	nsys = calloc(sizeof(struct netbus_sys), 1);
	peer = calloc(sizeof(peer_t), 1);

	if (!nsys || !peer)
		return NULL;

	peer->socket = socket(PF_INET, SOCK_STREAM, 0);
	if (peer->socket == -1) {
		jlog(L_ERROR, "netbus]> socket() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return NULL;
	}

        ret = setnonblocking(peer->socket);
        if (ret < 0) {
                jlog(L_ERROR, "netbus]> setnonblocking() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
                free(peer);
                return NULL;
        }

	memset(&addr_in, 0, sizeof(struct sockaddr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(port);
	addr_in.sin_addr.s_addr = inet_addr(addr);

	FD_SET(peer->socket, &wfds);
	errno = 0;

	ret = connect(peer->socket, (const struct sockaddr *)&addr_in, sizeof(const struct sockaddr));
	if (ret == -1) {
		if (errno == EINPROGRESS) {
			/* The socket is non-blocking and the
			 * connection cannot be completed immediately.
			 */
			ret = select(peer->socket + 1, NULL, &wfds, NULL, &tv);
			if (ret == 0) { /* TIMEOUT */
				jlog(L_DEBUG, "netbus]> connect() timed out :: %s:%i", __FILE__, __LINE__);
				close(peer->socket);
				free(peer);
				return NULL;
			}
			else {
				optlen = (socklen_t)sizeof(optval);
				/* use getsockopt(2) with SO_ERROR to check for error conditions */
				ret = getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, &optval, &optlen);
				if (ret == -1) {
					jlog(L_DEBUG, "netbus]> getsockopt() %s :: %s:%i", __FILE__, __LINE__);
					close(peer->socket);
					free(peer);
					return NULL;
				}

				if (optval != 0) { /* NOT CONNECTED ! TIMEOUT... */
					jlog(L_DEBUG, "netbus]> connect() timed out :: %s:%i", __FILE__, __LINE__);
					close(peer->socket);
					free(peer);
	                                return NULL;
				}
				else {
					/* ... connected, we continue ! */
				}
			}

		}
		else {
			jlog(L_DEBUG, "netbus]> connect() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
			close(peer->socket);
			free(peer);
			return NULL;
		}
	}

	peer->type = NETBUS_TCP_CLIENT;
	peer->on_disconnect = on_disconnect;
	peer->on_input = on_input;
	peer->send = netbus_send;
	peer->recv = netbus_recv;
	peer->disconnect = netbus_disconnect;
	peer->buffer = NULL;

	nsys->type = NETBUS_PEER;
	nsys->peer = peer;

	ret = ion_add(netbus_queue, peer->socket, nsys);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> ion_add() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return NULL;
	}

	return peer;
}

peer_t *netbus_ping_client(const char *addr, void (*on_pingreply)(peer_t *), void *ext_ptr)
{
	int ret, optval;
	struct in_addr dst;
	struct netbus_sys *nsys;
	peer_t *peer;

	if (netbus_queue == INVALID_Q) {
		jlog(L_NOTICE, "netbus]> subsystem unitialized :: %s:%i", __FILE__, __LINE__);
		return NULL;
	}

	nsys = calloc(sizeof(struct netbus_sys), 1);
	peer = calloc(sizeof(peer_t), 1);

	if (!nsys || !peer)
		return NULL;
	ret = inet_aton(addr, (struct in_addr *)&dst);

	peer->type = NETBUS_ICMP_PING;
	peer->ping = netbus_ping;
	peer->on_pingreply = on_pingreply;
	peer->dst = dst;
	peer->disconnect = netbus_disconnect;
	peer->ext_ptr = ext_ptr;
	peer->buffer = NULL;

	peer->socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (peer->socket < 0) {
		jlog(L_NOTICE, "netbus]> socket() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return NULL;

	}
	fcntl(peer->socket, F_SETOWN, (int)getpid());
	ret = setsockopt(peer->socket, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> setsockopt() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return NULL;
	}

	nsys->type = NETBUS_PEER;
	nsys->peer = peer;
	ret = ion_add(netbus_queue, peer->socket, nsys);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> ion_add() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return NULL;
	}

	jlog(L_NOTICE, "netbus]> new ping added");

	return peer;
}

int netbus_tcp_server(const char *in_addr,
		   const int port,
		   void (*on_connect)(peer_t*),
		   void (*on_disconnect)(peer_t*),
		   void (*on_input)(peer_t*),
		   void *ext_ptr)
{
	int ret;
	struct sockaddr_in addr;
	struct netbus_sys *nsys;
	peer_t *peer;

	if (netbus_queue == INVALID_Q) {
		jlog(L_NOTICE, "netbus]> subsystem unitialized :: %s:%i", __FILE__, __LINE__);
		return -1;
	}

	nsys = calloc(sizeof(struct netbus_sys), 1);
	peer = calloc(sizeof(peer_t), 1);

	if (!nsys || !peer)
		return -1;

	peer->type = NETBUS_TCP_SERVER;
	peer->on_connect = on_connect;
	peer->on_disconnect = on_disconnect;
	peer->on_input = on_input;
	peer->recv = netbus_recv;
	peer->send = netbus_send;
	peer->disconnect = netbus_disconnect;
	peer->buffer = NULL;
	peer->ext_ptr = ext_ptr;

	peer->socket = socket(PF_INET, SOCK_STREAM, 0);
	if (peer->socket < 0) {
		jlog(L_NOTICE, "netbus]> socket() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(in_addr);

	ret = setreuse(peer->socket);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> setreuse() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return -1;
	}

	ret = bind(peer->socket, (const struct sockaddr *)&addr, sizeof(const struct sockaddr));
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> bind() %s %s :: %s:%i", strerror(errno), in_addr, __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return -1;
	}

	/* The backlog parameter defines the maximum length the
	 * queue of pending connection may grow to. LISTEN(2)
	 */
	ret = listen(peer->socket, CONN_BACKLOG);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> set_nonblocking() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return -1;
	}

	nsys->type = NETBUS_PEER;
	nsys->peer = peer;
	ret = ion_add(netbus_queue, peer->socket, nsys);
	if (ret < 0) {
		jlog(L_NOTICE, "netbus]> ion_add() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		close(peer->socket);
		free(peer);
		return -1;
	}

	return 0;
}

void netbus_do_sched(void *udata)
{
	poke_queue(udata);
}

int netbus_init()
{
	/* Open an ion file descriptor */
	netbus_queue = ion_new();

	if (netbus_queue < 0) {
		jlog(L_NOTICE, "netbus]> ion_new() %s :: %s:%i", strerror(errno), __FILE__, __LINE__);
		netbus_queue = INVALID_Q;
		return -1;
	}

	sched_register(SCHED_APERIODIC, "netbus_do_sched", netbus_do_sched, 0, NULL);

#ifdef HAVE_UDT
	sched_register(SCHED_APERIODIC, "udtbus_poke_queue", udtbus_poke_queue, 0, NULL);
#endif
	return 0;
}
