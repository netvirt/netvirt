/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <list>

#include <pthread.h>
#include <udt.h>

#include "udt.h"
#include "logger.h"

// g++ udt.cpp -L/usr/local/lib -I../src/ -ludt -lstdc++ -lpthread -lm

#define UDTBUS_SERVER	0x1
#define UDTBUS_CLIENT	0x2

/* TODO
 * use journal function istead of count <<
 * handle errors
 */

using namespace std;
vector<UDTSOCKET>g_list_socket;

static void udtbus_ion_add(UDTSOCKET u)
{
	g_list_socket.push_back(u);
}

static void udtbus_disconnect(peer_t *peer)
{
	vector<UDTSOCKET>::iterator i;

	if (peer->socket > 0) {
		for (i = g_list_socket.begin(); i != g_list_socket.end(); ++i) {
			if (peer->socket == *i) {
				UDT::close(*i);
				g_list_socket.erase(i);
				break;
			}
		}
	}
	peer->buffer_data_len = 0;
	peer->ext_ptr = NULL;
	free(peer->buffer);
	free(peer);
}

static void on_disconnect(peer_t *peer)
{
	vector<UDTSOCKET>::iterator i;

	for (i = g_list_socket.begin(); i != g_list_socket.end(); ++i) {
		if (peer->socket == *i) {
			UDT::close(*i);
			g_list_socket.erase(i);
			break;
		}
	}
	peer->socket = 0;

	// inform upper layer
	if (peer->on_disconnect)
		peer->on_disconnect(peer);

	udtbus_disconnect(peer);
}

static int udtbus_send(peer_t *peer, void *data, int len)
{
	vector<UDTSOCKET>::iterator i;
	vector<UDTSOCKET> list_socket;
	vector<UDTSOCKET> exceptfds;

	list_socket.push_back(peer->socket);

	int res = UDT::selectEx(list_socket, NULL, NULL, &exceptfds, 0);
	if (res != 0) {
		for (i = exceptfds.begin(); i != exceptfds.end(); ++i) {
			if (peer->socket == *i) {
				jlog(L_NOTICE, "send: %s", UDT::getlasterror().getErrorMessage());
				on_disconnect(peer);
				return -1;
			}
		}
	}

	int ret = UDT::send(peer->socket, (char*)data, len, 0);
	if (ret == UDT::ERROR) {
		jlog(L_WARNING, "send: %s", UDT::getlasterror().getErrorMessage());
		on_disconnect(peer);
		return -1;
	}

	return ret;
}

static int udtbus_recv(peer_t *peer)
{
	int size = 5000; // FIXME use dynamic buffer

	if (peer->buffer == NULL) {
		peer->buffer = malloc(size);
	}

	int rs = UDT::recv(peer->socket, (char *)peer->buffer, size, 0);
	if (rs == UDT::ERROR) {
		jlog(L_WARNING, "recv: %s", UDT::getlasterror().getErrorMessage());
		return -1;
	}

	return rs;
}

static void on_input(peer_t *peer)
{
	peer->on_input(peer);
}

static void on_connect(peer_t *peer)
{
	UDTSOCKET client;
	peer_t *npeer;
	int mss = 1450;

	sockaddr_storage clientaddr;
	int addrlen = sizeof(clientaddr);

	client = UDT::accept(peer->socket, (sockaddr*)&clientaddr, &addrlen);
	UDT::setsockopt(client, 0, UDT_MSS, &mss, sizeof(int));
	if (client == UDT::INVALID_SOCK) {
		jlog(L_WARNING, "accept: %s", UDT::getlasterror().getErrorMessage());
		return;
	}

	char clienthost[NI_MAXHOST];
	char clientservice[NI_MAXSERV];

	getnameinfo((sockaddr *)&clientaddr,
				 addrlen,
				clienthost,
				sizeof(clienthost),
				clientservice,
				sizeof(clientservice),
				NI_NUMERICHOST|NI_NUMERICSERV);

	jlog(L_NOTICE, "new connection from: %s:%s", clienthost, clientservice);

	npeer = (peer_t *)calloc(sizeof(peer_t), 1);
	npeer->type = UDTBUS_CLIENT;
	npeer->socket = (int)client;
	npeer->on_connect = peer->on_connect;
	npeer->on_disconnect = peer->on_disconnect;
	npeer->on_input = peer->on_input;
	npeer->recv = udtbus_recv;
	npeer->send = udtbus_send;
	npeer->disconnect = udtbus_disconnect;
	npeer->buffer = NULL;
	npeer->buffer_offset = 0;
	npeer->host = strdup(clienthost);
	npeer->host_len = strlen(npeer->host);
	npeer->port = atoi(clientservice);

	npeer->ext_ptr = peer->ext_ptr;

	UDT::set_ext_ptr(client, (void*)npeer);
	udtbus_ion_add(client);
	npeer->on_connect(npeer);
}

void udtbus_poke_queue()
{
	peer_t *peer;

	vector<UDTSOCKET> readfds;
	vector<UDTSOCKET> exceptfds;
	vector<UDTSOCKET>::iterator i;

	int res = UDT::selectEx(g_list_socket, &readfds, NULL, &exceptfds, 0);
	if (res == 0) // no socket is ready before timeout
		return;

	// socket that are ready for receive
	for (i = readfds.begin(); i != readfds.end(); ++i) {

		peer = (peer_t*)UDT::get_ext_ptr(*i);
		if (peer == NULL)
			continue;

		if (peer->type == UDTBUS_SERVER) {
			on_connect(peer);
		}
		else if (peer->type == UDTBUS_CLIENT) {
			on_input(peer);
		}
	}

	// socket that are closed or with a broken connection
	for (i = exceptfds.begin(); i != exceptfds.end(); ++i) {

		peer = (peer_t*)UDT::get_ext_ptr(*i);
		if (peer == NULL)
			continue;

		jlog(L_NOTICE, "peer <socket:%d> closed or broken connection", peer->socket);
		on_disconnect(peer);
	}
}

peer_t *udtbus_client(const char *listen_addr,
				const char *port,
				void (*on_disconnect)(peer_t *),
				void (*on_input)(peer_t *))
{
	struct addrinfo hints, *local, *serv_info;
	int ret = 0;
	int mss = 1450;

	peer_t *peer;
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(NULL, port, &hints, &local);

	UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);
	UDT::setsockopt(client, 0, UDT_MSS, &mss, sizeof(int));

	freeaddrinfo(local);
	ret = getaddrinfo(listen_addr, port, &hints, &serv_info);
	if (ret != 0) {
		jlog(L_WARNING, "getaddrinfo failed: %s", gai_strerror(ret));
		UDT::close(client);
		return NULL;
	}

	if (UDT::connect(client, serv_info->ai_addr, serv_info->ai_addrlen) == UDT::ERROR) {
		jlog(L_WARNING, "%s", UDT::getlasterror().getErrorMessage());
		freeaddrinfo(serv_info);
		UDT::close(client);
		return NULL;
	}

	freeaddrinfo(serv_info);

	peer = (peer_t *)calloc(sizeof(peer_t), 1);
	peer->type = UDTBUS_CLIENT;
	peer->socket = client;
	peer->on_connect = NULL;
	peer->on_disconnect = on_disconnect;
	peer->on_input = on_input;
	peer->recv = udtbus_recv;
	peer->send = udtbus_send;
	peer->disconnect = udtbus_disconnect;
	peer->buffer = NULL;

	UDT::set_ext_ptr(client, (void*)peer);
	udtbus_ion_add(client);

	return peer;
}

int udtbus_server(const char *listen_addr,
                  const char *port,
                  void (*on_connect)(peer_t *),
                  void (*on_disconnect)(peer_t *),
                  void (*on_input)(peer_t *),
                  void *ext_ptr)
{
	peer_t *peer;

	addrinfo hints;
	addrinfo* res;
	int ret = 0;
	int mss = 1450;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(listen_addr, port, &hints, &res);

	if (ret) {
		jlog(L_ERROR, "illegal port number or port is busy: %s", gai_strerror(ret));
		return -1;
	}

	UDTSOCKET serv = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	bool block = false;
	UDT::setsockopt(serv, 0, UDT_RCVSYN, &block, sizeof(bool));

	UDT::setsockopt(serv, 0, UDT_MSS, &mss, sizeof(int));
	if (UDT::bind(serv, res->ai_addr, res->ai_addrlen) == UDT::ERROR) {
		jlog(L_WARNING, "bind: %s", UDT::getlasterror().getErrorMessage());
		return -1;
	}

	freeaddrinfo(res);
	jlog(L_NOTICE, "server is listening on port: %s", port);

	if (UDT::listen(serv, 10) == UDT::ERROR) {

		jlog(L_NOTICE, "listen: %s", UDT::getlasterror().getErrorMessage());
		return -1;
	}

	peer = (peer_t *)calloc(sizeof(peer_t), 1);
	peer->type = UDTBUS_SERVER;
	peer->socket = serv;
	peer->on_connect = on_connect;
	peer->on_disconnect = on_disconnect;
	peer->on_input = on_input;
	peer->recv = udtbus_recv;
	peer->send = udtbus_send;
	peer->disconnect = udtbus_disconnect;
	peer->buffer = NULL;
	peer->ext_ptr = ext_ptr;

	UDT::set_ext_ptr(serv, (void*)peer);
	udtbus_ion_add(serv);

	return 0;
}

void *udtbus_rendezvous(void *args)
{
	int ret = 0;
	peer_t *peer = NULL;
	uint8_t p2p_failed = 0;
	uint8_t nb_port = 0;
	uint8_t port_itr = 0;
	struct addrinfo hints, *local, *server;
	struct p2p_args *p2p_args = (struct p2p_args *)args;
	int mss = 1450;
	bool rdv = true;

	nb_port = sizeof(p2p_args->port)/sizeof(p2p_args->port[0]);

retry:
	jlog(L_NOTICE, "trying port %s...", p2p_args->port[port_itr]);
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(p2p_args->listen_addr, p2p_args->port[port_itr], &hints, &local);
	if (ret != 0) {
		jlog(L_WARNING, "illegal port number or port is busy: %s", gai_strerror(ret));
		freeaddrinfo(local);
		return NULL;
	}

	UDTSOCKET socket = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

	UDT::setsockopt(socket, 0, UDT_MSS, &mss, sizeof(int));
	UDT::setsockopt(socket, 0, UDT_RENDEZVOUS, &rdv, sizeof(bool));
	if (UDT::ERROR == UDT::bind(socket, local->ai_addr, local->ai_addrlen)) {
		jlog(L_WARNING, "bind: %s", UDT::getlasterror().getErrorMessage());
		freeaddrinfo(local);
		return NULL;
	}

	freeaddrinfo(local);

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(p2p_args->dest_addr, p2p_args->port[port_itr], &hints, &server);
	if (ret != 0) {
		jlog(L_WARNING, "incorrect server address: %s", gai_strerror(ret));
		freeaddrinfo(server);
		return NULL;
	}

	if (UDT::connect(socket, server->ai_addr, server->ai_addrlen) == UDT::ERROR) {
		jlog(L_ERROR, "%s", UDT::getlasterror().getErrorMessage());
		UDT::close(socket);

		if (port_itr < nb_port-1) {
			port_itr++;
			goto retry;
		}

		p2p_failed = 1;
	}

	freeaddrinfo(server);

	peer = (peer_t *)calloc(sizeof(peer_t), 1);
	peer->type = UDTBUS_CLIENT;
	peer->socket = socket;
	peer->on_connect = p2p_args->on_connect;
	peer->on_disconnect = p2p_args->on_disconnect;
	peer->on_input = p2p_args->on_input;
	peer->recv = udtbus_recv;
	peer->send = udtbus_send;
	peer->disconnect = udtbus_disconnect;
	peer->buffer = NULL;
	peer->buffer_offset = 0;
	peer->ext_ptr = p2p_args->ext_ptr;

	free(p2p_args->listen_addr);
	free(p2p_args->dest_addr);
	free(p2p_args->port[0]);
	free(p2p_args->port[1]);
	free(p2p_args->port[2]);
	free(p2p_args);

	if (p2p_failed) {
		/* this seem a bit redundant, but it keeps the logic flow clear
		   without using any obscure shortcut to free everything in case
		   of a p2p failure */
		jlog(L_NOTICE, "p2p failed");
		on_disconnect(peer);
		return NULL;
	}

	UDT::set_ext_ptr(socket, (void *)peer);
	udtbus_ion_add(socket);

	peer->on_connect(peer);

	return NULL;
}

extern "C" void udtbus_fini()
{
	// use this function to release the UDT library
	UDT::cleanup();

	return;
}

int udtbus_init()
{
	// use this function to initialize the UDT library
	UDT::startup();

#ifdef _WIN32
	int iResult;
	WSADATA wsaData;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return -1;
	}
#endif
	return 0;
}
