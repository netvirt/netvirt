#ifndef DNDS_UDTBUS_H
#define DNDS_UDTBUS_H

#include "netbus.h"

void udt_fini();
int udtbus_init();
peer_t *udtbus_client(const char *, const char *, void (*)(peer_t *), void (*)(peer_t *));
int udtbus_server(const char *listenaddr, const char *port, void (*)(), void (*)(), void (*)(), void *);
peer_t *udtbus_rendezvous(const char *listen_addr, const char *dest_addr, const char *port, void (*on_disconnect)(peer_t *), void (*on_input)(peer_t *), void *ext_ptr);
void udtbus_poke_queue(void*);

#endif // DNDS_UDTBUS_H
