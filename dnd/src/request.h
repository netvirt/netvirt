#ifndef DND_REQUEST_H
#define DND_REQUEST_H

#include <dnds/dnds.h>
#include "session.h"

int authRequest(session_t *session, DNDSMessage_t *msg);
void p2pRequest(session_t *session, DNDSMessage_t *msg);

#endif /* DND_REQUEST_H */
