/*
 * udtbus: Low level UDT network API
 *
 * Copyright (C) Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <iostream>
#include <list>

#include <pthread.h>
#include <udt.h>

#include "udt.h"

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

	for (i = g_list_socket.begin(); i != g_list_socket.end(); ++i) {
		if (peer->socket == *i) {
			UDT::close(*i);
			g_list_socket.erase(i);
			free(peer);
			break;
		}
	}
}

static void on_disconnect(peer_t *peer)
{
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
				cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
				on_disconnect(peer);
				return -1;
			}
		}
	}

	int ret = UDT::send(peer->socket, (char*)data, len, 0);

	if (ret == UDT::ERROR) {
		cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
		on_disconnect(peer);
		return -1;
	}

	return ret;
}

static int udtbus_recv(peer_t *peer)
{
	int size = 1000000; // FIXME use dynamic buffer

	if (peer->buffer == NULL) {
		peer->buffer = malloc(size);
	}

	int rs = UDT::recv(peer->socket, (char *)peer->buffer, size, 0);
	if (rs == UDT::ERROR) {
		cout << "recv:" << UDT::getlasterror().getErrorMessage();
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

	sockaddr_storage clientaddr;
	int addrlen = sizeof(clientaddr);

	client = UDT::accept(peer->socket, (sockaddr*)&clientaddr, &addrlen);
	if (client == UDT::INVALID_SOCK) {
		cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
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

	cout << "new connection: " << clienthost << ":" << clientservice << endl;

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

extern "C" void udtbus_poke_queue()
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

		on_disconnect(peer);
	}
}

extern "C" peer_t *udtbus_client(const char *listen_addr,
				const char *port,
				void (*on_disconnect)(peer_t *),
				void (*on_input)(peer_t *))
{
	int ret;
	struct addrinfo hints, *local, *serv_info;

	peer_t *peer;
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(NULL, port, &hints, &local);

	UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

	freeaddrinfo(local);
	ret = getaddrinfo(listen_addr, port, &hints, &serv_info);

	if (UDT::connect(client, serv_info->ai_addr, serv_info->ai_addrlen) == UDT::ERROR) {
		cout << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
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

extern "C" int udtbus_server(const char *listen_addr,
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

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(listen_addr, port, &hints, &res);

	if (ret) {
		cout << "illegal port number or port is busy (" << gai_strerror(ret) << ")" << endl;
		return -1;
	}

	UDTSOCKET serv = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	bool block = false;
	UDT::setsockopt(serv, 0, UDT_RCVSYN, &block, sizeof(bool));

	if (UDT::bind(serv, res->ai_addr, res->ai_addrlen) == UDT::ERROR) {

		cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
		return -1;
	}

	freeaddrinfo(res);
	cout << "server is ready at port: " << port << endl;

	if (UDT::listen(serv, 10) == UDT::ERROR) {

		cout << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
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

// FIXME need to be tested with DNDSMessage
extern "C" peer_t *udtbus_rendezvous(const char *listen_addr,
				const char *dest_addr,
				const char *port,
				void (*on_disconnect)(peer_t *),
				void (*on_input)(peer_t *),
				void *ext_ptr) {

	int ret = 0;
	peer_t *peer = NULL;
	struct addrinfo hints, *local, *server;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(listen_addr, port, &hints, &local);
	if (ret != 0) {
		cout << "illegal port number or port is busy (" << gai_strerror(ret) << ")" << endl;
		return NULL;
	}

	UDTSOCKET socket = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

	UDT::setsockopt(socket, 0, UDT_RENDEZVOUS, new bool(true), sizeof(bool));
	if (UDT::ERROR == UDT::bind(socket, local->ai_addr, local->ai_addrlen)) {
		cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
		return NULL;
	}

	freeaddrinfo(local);

	ret = getaddrinfo(dest_addr, port, &hints, &server);
	if (ret != 0) {
		cout << "incorrect server address (" << gai_strerror(ret) << ")" << endl;
		return NULL;
	}

	if (UDT::connect(socket, server->ai_addr, server->ai_addrlen) == UDT::ERROR) {
		cout << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
		return NULL;
	}

	freeaddrinfo(server);

	peer = (peer_t *)malloc(sizeof(peer_t));
	peer->type = UDTBUS_CLIENT;
	peer->socket = socket;
	peer->on_connect = NULL;
	peer->on_disconnect = on_disconnect;
	peer->on_input = on_input;
	peer->recv = udtbus_recv;
	peer->send = udtbus_send;
	peer->disconnect = udtbus_disconnect;
	peer->buffer = NULL;
	peer->ext_ptr = ext_ptr;

	UDT::set_ext_ptr(socket, (void *)peer);

	udtbus_ion_add(socket);

	return peer;
}

extern "C" void udtbus_fini()
{
	// use this function to release the UDT library
	UDT::cleanup();

	return;
}

extern "C" int udtbus_init()
{
	// use this function to initialize the UDT library
	UDT::startup();

	return 0;
}
