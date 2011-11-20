#ifndef DND_SESSION_H
#define DND_SESSION_H

#include "context.h"

typedef struct session {

	char *ip;
	uint8_t auth;

        char ip_local[16];
        uint8_t tun_mac_addr[6];

	netc_t *netc;
	struct context *context;

	// FIXME should we support a mac list ?
	uint8_t mac_addr[6];

	struct session *next;
	struct session *prev;

} session_t;

session_t *session_new();
void session_free(session_t *session);
void session_terminate(session_t *session);
void *session_itemdup(const void *item);
void session_itemrel(void *item);

#endif /* DND_SESSION_H */
