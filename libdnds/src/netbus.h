#ifndef NETBUS_H
#define NETBUS_H

#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

typedef struct peer {

	int type;
	int socket;
	struct in_addr dst; // FIXME - should we trash this?
	struct sockaddr_in peername; // FIXME - should we trash this?

	char *host;
	uint16_t host_len;
	uint16_t port;

	void (*on_connect)(struct peer *);
	void (*on_disconnect)(struct peer *);
	void (*on_input)(struct peer *);

	void (*on_pingreply)(struct peer *);

	int (*ping)();
	int (*send)(struct peer *, void *, int);
	int (*recv)(struct peer *);
	void (*disconnect)(struct peer *);

	void *buffer;
	uint32_t buffer_data_len;
	size_t buffer_offset;
	void *ext_ptr;

} peer_t;

extern peer_t *netbus_ping_client(const char *, void (*)(peer_t *), void *);

extern peer_t *netbus_tcp_client(const char *, const int, void (*)(peer_t*), void (*)(peer_t*));
extern int netbus_tcp_server(const char *, const int, void (*)(), void (*)(), void (*)(), void *); 

typedef struct iface {
	
	char devname[16];
	int fd;

	void (*on_input)();

	int (*write)(struct iface *, void *, int);
	int (*read)(struct iface *);
	void (*shutdown)();

	void *frame;
	void *ext_ptr;

} iface_t;

extern iface_t *netbus_newtun(void (*)(iface_t *));

#define NETBUS_PEER 0x1
#define NETBUS_IFACE 0x4
struct netbus_sys {

	int type;

	peer_t *peer;
	iface_t *iface;
};

extern void netbus_do_sched(void *);
extern int netbus_init();

#endif /* NETBUS_H */
