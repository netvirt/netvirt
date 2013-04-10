#ifndef DND_IPPOOL_H
#define DND_IPPOOL_H

#include <netinet/in.h>

typedef struct ippool {

	uint32_t hosts;

	struct in_addr hostmin;
	struct in_addr hostmax;

	struct in_addr address;
	struct in_addr netmask;

	uint8_t *pool;

} ippool_t;

extern char *ippool_get_ip(ippool_t *);
extern void ippool_release_ip(ippool_t *, char *);
extern ippool_t *ippool_new(char *, char *);

#endif /* DND_IPPOOL_H */
