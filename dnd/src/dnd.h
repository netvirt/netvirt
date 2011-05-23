#ifndef DND_DND_H
#define DND_DND_H

#include <dnds/net.h>
#include "context.h"

#define SESS_NOT_AUTHENTICATED	0x01
#define SESS_WAIT_STEP_UP	0x02
#define SESS_AUTHENTICATED	0x04

extern int dnd_init(char *listen_addr, char *port);

#endif /* DND_DND_H */
