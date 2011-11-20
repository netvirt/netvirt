#ifndef DNC_SESSION_H
#define DNC_SESSION_H

#include <dnds/net.h>
#include <dnds/netbus.h>

#define	SESS_AUTH	0x1
#define SESS_NOT_AUTH	0x2
#define SESS_WAIT_RESPONSE 0x4

// session type
#define SESS_TYPE_CLIENT	0x1
#define SESS_TYPE_SERVER	0x2
#define SESS_TYPE_P2P_CLIENT	0x3
#define SESS_TYPE_P2P_SERVER	0x4

typedef struct {
	uint8_t auth;
	uint8_t type;

	char ip_local[16];
	uint8_t tun_mac_addr[6];

	iface_t *iface;
	peer_t *peer;
	netc_t *netc;

} dn_sess_t;

void *session_itemdup(const void *item);
void session_itemrel(void *item);

#endif /* DNC_SESSION_H */
