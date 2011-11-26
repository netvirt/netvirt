#ifndef DND_CONTEXT_H
#define DND_CONTEXT_H

#include <dnds/ftable.h>
#include <dnds/netbus.h>
#include <dnds/mbuf.h>

#include "dnd.h"
#include "ippool.h"

typedef struct context {

	int id;					// context unique identifier
	ftable_t *ftable;			// forwarding table

	ippool_t *ippool;			// ip address pool
	uint8_t *bitpool;			// bitpool used to generated unique ID per session

	struct session *session_list;		// all session open in this context

} context_t;

void context_del_session(context_t *ctx, struct session *session);
void context_add_session(context_t *ctx, struct session *session);
context_t *context_lookup(uint32_t id);

void context_fini(void *ext_ptr);
int context_init();


#endif /* DND_CONTEXT_H */
