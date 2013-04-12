#ifndef DND_CONTEXT_H
#define DND_CONTEXT_H

#include <krypt.h>
#include <netbus.h>
#include <mbuf.h>

#include "dnd.h"
#include "ftable.h"
#include "linkst.h"

typedef struct context {

	int id;					// context unique identifier
	ftable_t *ftable;			// forwarding table

	uint8_t **linkst;			// linkstate adjacency matrix
	uint8_t *bitpool;			// bitpool used to generated unique ID per session

	struct session *session_list;		// all session open in this context

	passport_t *passport;

} context_t;

int context_create(uint32_t id, char *address, char *netmask,
			char *serverCert, char *serverPrivkey, char *trustedCert);
void context_del_session(context_t *ctx, struct session *session);
void context_add_session(context_t *ctx, struct session *session);
context_t *context_lookup(uint32_t id);

void context_fini(void *ext_ptr);
int context_init();


#endif /* DND_CONTEXT_H */
