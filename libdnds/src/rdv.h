/*
 * See COPYRIGHTS file.
 */

#ifndef RDV_H
#define RDV_H

#include <stdint.h>

#include <netinet/in.h>

#define RDV_VERSION	0x1

#define RDV_STATE_LISTEN	0x1
#define RDV_STATE_CONNECT	0x2

enum {
	RDV_REQUEST_ASK = 0,	// rendez-vous ask
	RDV_REQUEST_MEETAT,	// rendez-vous meet-at
	RDV_REQUEST_DENY	// rendez-vous denied
};

struct rdv {
	uint16_t version;
	uint32_t length;
	uint16_t type;
} __attribute__((__packed__));

// rendez-vous ask
#define RDV_ASK_LENGTH 28
typedef struct {
	uint8_t local_ip[16];
	uint8_t src_mac[6];
	uint8_t dest_mac[6];
} __attribute__((__packed__)) RDV_ASK;

// rendez-vous meet-at
#define RDV_MEETAT_LENGTH 26
typedef struct {
	uint8_t dest_mac[6];
	uint8_t dest_ip[16];
	uint16_t port;
	uint16_t state; // LISTEN or ACCEPT
} __attribute__((__packed__)) RDV_MEETAT;

// rendez-vous denied
typedef struct {
} __attribute__((__packed__)) RDV_DENIED;

static inline void rdv_hton(struct rdv *rdv) {
	RDV_ASK *rdv_ask = NULL;
	RDV_MEETAT *rdv_meetat = NULL;

	switch (rdv->type) {
		case RDV_REQUEST_ASK:
			rdv_ask = (RDV_ASK *)((uint8_t *)rdv + sizeof(struct rdv));
			break;
		case RDV_REQUEST_MEETAT:
			rdv_meetat = (RDV_MEETAT *)((uint8_t *)rdv + sizeof(struct rdv));
			rdv_meetat->port = htons(rdv_meetat->port);
			rdv_meetat->state = htons(rdv_meetat->state);
			break;
	}

	rdv->version = htons(rdv->version);
	rdv->length = htonl(rdv->length);
	rdv->type = htons(rdv->type);
}

static inline void rdv_ntoh(struct rdv *rdv) {
	RDV_ASK *rdv_ask = NULL;
	RDV_MEETAT *rdv_meetat = NULL;

	rdv->version = ntohs(rdv->version);
	rdv->length = ntohl(rdv->length);
	rdv->type = ntohs(rdv->type);

	switch (rdv->type) {
		case RDV_REQUEST_ASK:
			rdv_ask = (RDV_ASK *)((uint8_t *)rdv + sizeof(struct rdv));
			break;
		case RDV_REQUEST_MEETAT:
			rdv_meetat = (RDV_MEETAT *)((uint8_t *)rdv + sizeof(struct rdv));
			rdv_meetat->port = ntohs(rdv_meetat->port);
			rdv_meetat->state = ntohs(rdv_meetat->state);
			break;
	}
}

struct rdv *rdv_ask(char *local_ip, uint8_t *source_mac, uint8_t *destination_mac);
struct rdv *rdv_meetat(uint8_t *destination_mac, const char *destination_ip, const char *port, uint16_t state);
void rdv_print(struct rdv *rdv_request);

#endif
