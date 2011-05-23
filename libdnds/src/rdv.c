/*
 * See COPYRIGHTS file.
 */

/* FIXME
 * this subsystem is obsolete
 */

#include <stdlib.h>
#include <string.h>

#include "journal.h"
#include "rdv.h"

static struct rdv *rdv_encapsulate(uint16_t version, uint16_t type, void *request, uint16_t request_len) {
	struct rdv *rdv_request;

	rdv_request = (struct rdv *)malloc(sizeof(struct rdv) + request_len);
	rdv_request->version = version;
	rdv_request->type = type;
	rdv_request->length = sizeof(struct rdv);

	switch (type) {
		case RDV_REQUEST_ASK:
			rdv_request->length += request_len;
			break;
		case RDV_REQUEST_MEETAT:
			rdv_request->length += request_len;
			break;
		default:
			// TODO - error
			break;
	}

	memmove(((uint8_t *)rdv_request) + sizeof(struct rdv), request, request_len);

	return rdv_request;
}

void rdv_print(struct rdv *rdv_request) {
	JOURNAL_DEBUG("rdv]> printing rdv_request");

	RDV_ASK *rdv_ask;
	RDV_MEETAT *rdv_meetat;

	if (rdv_request == NULL) {
		JOURNAL_DEBUG("rdv]> NULL");
	}
	else {
		JOURNAL_DEBUG("rdv]> version: %d", rdv_request->version);
		JOURNAL_DEBUG("rdv]> length: %d", rdv_request->length);

		switch (rdv_request->type) {
			case RDV_REQUEST_ASK:
				rdv_ask = (RDV_ASK *)(rdv_request + sizeof(struct rdv));
				JOURNAL_DEBUG("rdv]> type: ask");
				JOURNAL_DEBUG("rdv]> destination mac: %02x:%02x:%02x:%02x:%02x:%02x", rdv_ask->dest_mac[0],
													rdv_ask->dest_mac[1],
													rdv_ask->dest_mac[2],
													rdv_ask->dest_mac[3],
													rdv_ask->dest_mac[4],
													rdv_ask->dest_mac[5]);
				break;
			case RDV_REQUEST_MEETAT:
				rdv_meetat = (RDV_MEETAT *)(rdv_request + sizeof(struct rdv));
				JOURNAL_DEBUG("rdv]> type: meetat");
				JOURNAL_DEBUG("rdv]> destination mac: %02x:%02x:%02x:%02x:%02x:%02x", rdv_meetat->dest_mac[0],
													rdv_meetat->dest_mac[1],
													rdv_meetat->dest_mac[2],
													rdv_meetat->dest_mac[3],
													rdv_meetat->dest_mac[4],
													rdv_meetat->dest_mac[5]);
				JOURNAL_DEBUG("rdv]> destination ip: %s", rdv_meetat->dest_ip);
				JOURNAL_DEBUG("rdv]> destination port: %d", rdv_meetat->port);
				break;
			default:
				JOURNAL_DEBUG("rdv]> type: unknown (%d)", rdv_request->type);
				break;
		}
	}
}

struct rdv *rdv_ask(char *local_ip, uint8_t *source_mac, uint8_t *destination_mac) {
	struct rdv *request;
	RDV_ASK ask;

	memcpy(ask.local_ip, local_ip, 16);
	memcpy(ask.src_mac, source_mac, 6);
	memcpy(ask.dest_mac, destination_mac, 6);

	request = rdv_encapsulate(RDV_VERSION, RDV_REQUEST_ASK, &ask, RDV_ASK_LENGTH);

	return request;
}

struct rdv *rdv_meetat(uint8_t *destination_mac, const char *destination_ip, const char *port, uint16_t state) {
	struct rdv *request;
	RDV_MEETAT meetat;

	memcpy(meetat.dest_mac, destination_mac, 6);
	memcpy(meetat.dest_ip, destination_ip, 16);
	meetat.port = atoi(port);
	meetat.state = state;

	request = rdv_encapsulate(RDV_VERSION, RDV_REQUEST_MEETAT, &meetat, RDV_MEETAT_LENGTH);

	return request;
}
