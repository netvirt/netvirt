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

struct p2p_args {

	const char *listen_addr;
	const char *dest_addr;
	char *port[3];
	void (*on_connect)(struct peer *);
	void (*on_disconnect)(struct peer *);
	void (*on_input)(struct peer *);
	void *ext_ptr;
};

#ifdef __cplusplus
extern "C" {
#endif

int udtbus_server(const char *listen_addr,
                  const char *port,
                  void (*on_connect)(peer_t *),
                  void (*on_disconnect)(peer_t *),
                  void (*on_input)(peer_t *),
                  void *ext_ptr);

void *udtbus_rendezvous(void *args);

peer_t *udtbus_client(const char *listen_addr,
                      const char *port,
                      void (*on_disconnect)(peer_t *),
                      void (*on_input)(peer_t *));
void udtbus_poke_queue();
int udtbus_init();

#ifdef __cplusplus
}
#endif

#endif
