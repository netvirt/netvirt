#ifndef DNDS_UDTBUS_H
#define DNDS_UDTBUS_H

#include <stdint.h>

typedef struct peer {

	int type;
	int socket;

	char *host;
	uint16_t host_len;
	uint16_t port;

	void (*on_connect)(struct peer *);
	void (*on_disconnect)(struct peer *);
	void (*on_input)(struct peer *);

	int (*ping)();
	int (*send)(struct peer *, void *, int);
	int (*recv)(struct peer *);
	void (*disconnect)(struct peer *);

	void *buffer;
	uint32_t buffer_data_len;
	size_t buffer_offset;
	void *ext_ptr;

} peer_t;

#ifdef __cplusplus
extern "C"
#endif
peer_t *udtbus_client(const char *listen_addr,
                                 const char *port,
                                 void (*on_disconnect)(peer_t *),
                                 void (*on_input)(peer_t *));

#endif
