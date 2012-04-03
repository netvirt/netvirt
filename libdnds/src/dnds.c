/*
 * dnds.c: Dynamic Network Directory Service Protocol API
 *
 * Copyright (C) 2010, 2011 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include "asn1/DNDSMessage.h"
#include "dnds.h"

/* TODO
 * check for DNDS_value_not_present (on id ?)
 */

// DNDSMessage
int DNDSMessage_new(DNDSMessage_t **msg)
{
	*msg = calloc(1, sizeof(DNDSMessage_t));

	if (*msg == NULL) {
		return DNDS_alloc_failed;
	}

	(*msg)->version = 1;

	return DNDS_success;
}

int DNDSMessage_del(DNDSMessage_t *msg)
{
	asn_DEF_DNDSMessage.free_struct(&asn_DEF_DNDSMessage, msg, 0);
	return DNDS_success;
}

int DNDSMessage_set_channel(DNDSMessage_t *msg, uint8_t channel)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	msg->channel = channel;

	return DNDS_success;
}

int DNDSMessage_get_channel(DNDSMessage_t *msg, uint8_t *channel)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	*channel = msg->channel;

	return DNDS_success;
}

int DNDSMessage_set_pdu(DNDSMessage_t *msg, pdu_PR pdu)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	msg->pdu.present = pdu;

	return DNDS_success;
}

int DNDSMessage_get_pdu(DNDSMessage_t *msg, pdu_PR *pdu)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	*pdu = msg->pdu.present;

	return DNDS_success;
}

int DNDSMessage_set_ethernet(DNDSMessage_t *msg, uint8_t *frame, size_t length)
{
	msg->pdu.choice.ethernet.buf = frame;
	msg->pdu.choice.ethernet.size = length;
}

int DNDSMessage_get_ethernet(DNDSMessage_t *msg, uint8_t **frame, size_t *length)
{
	*frame = msg->pdu.choice.ethernet.buf;
	*length = msg->pdu.choice.ethernet.size;
}

// DNMessage
int DNMessage_set_seqNumber(DNDSMessage_t *msg, uint32_t seqNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	msg->pdu.choice.dnm.seqNumber = seqNumber;

	return DNDS_success;
}

int DNMessage_get_seqNumber(DNDSMessage_t *msg, uint32_t *seqNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	*seqNumber = msg->pdu.choice.dnm.seqNumber;

	return DNDS_success;
}

int DNMessage_set_ackNumber(DNDSMessage_t *msg, uint32_t ackNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	msg->pdu.choice.dnm.ackNumber = ackNumber;

	return DNDS_success;
}

int DNMessage_get_ackNumber(DNDSMessage_t *msg, uint32_t *ackNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	*ackNumber = msg->pdu.choice.dnm.ackNumber;

	return DNDS_success;
}

int DNMessage_set_operation(DNDSMessage_t *msg, dnop_PR operation)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	msg->pdu.choice.dnm.dnop.present = operation;

	return DNDS_success;
}

int DNMessage_get_operation(DNDSMessage_t *msg, dnop_PR *operation)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	*operation = msg->pdu.choice.dnm.dnop.present;

	return DNDS_success;
}

// DSMessage
int DSMessage_set_seqNumber(DNDSMessage_t *msg, uint32_t seqNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	msg->pdu.choice.dsm.seqNumber = seqNumber;

	return DNDS_success;
}

int DSMessage_get_seqNumber(DNDSMessage_t *msg, uint32_t *seqNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	*seqNumber = msg->pdu.choice.dsm.seqNumber;

	return DNDS_success;
}

int DSMessage_set_ackNumber(DNDSMessage_t *msg, uint32_t ackNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	msg->pdu.choice.dsm.ackNumber = ackNumber;

	return DNDS_success;
}

int DSMessage_get_ackNumber(DNDSMessage_t *msg, uint32_t *ackNumber)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	*ackNumber = msg->pdu.choice.dsm.ackNumber;

	return DNDS_success;
}

int DSMessage_set_operation(DNDSMessage_t *msg, dsop_PR operation)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	msg->pdu.choice.dsm.dsop.present = operation;

	return DNDS_success;
}

int DSMessage_get_operation(DNDSMessage_t *msg, dsop_PR *operation)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	*operation = msg->pdu.choice.dsm.dsop.present;

	return DNDS_success;
}

// DNDSObject
int DNDSObject_set_objectType(DNDSObject_t *object, DNDSObject_PR type)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	object->present = type;

	return DNDS_success;
}

int DNDSObject_get_objectType(DNDSObject_t *object, DNDSObject_PR *objType)
{
	if (object == NULL || objType == NULL) {
		return DNDS_invalid_param;
	}

	*objType = object->present;

	return DNDS_success;
}

// ContextInfo
int ContextInfo_set_id(DNDSMessage_t *msg, uint32_t id)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.id = id;

	return DNDS_success;
}

int ContextInfo_get_id(DNDSMessage_t *msg, uint32_t *id)
{
	if (msg == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	*id = msg->pdu.choice.dsm.dsop.choice.contextInfo.id;

	return DNDS_success;
}

int ContextInfo_set_topology(DNDSMessage_t *msg, e_Topology topology)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.topology = topology;

	return DNDS_success;
}

int ContextInfo_get_topology(DNDSMessage_t *msg, e_Topology *topology)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	*topology = msg->pdu.choice.dsm.dsop.choice.contextInfo.topology;

	return DNDS_success;
}

int ContextInfo_set_description(DNDSMessage_t *msg, const char *description, size_t length)
{
	if (msg == NULL || description == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.description = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (msg->pdu.choice.dsm.dsop.choice.contextInfo.description == NULL) {
		return DNDS_alloc_failed;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.description->buf = strdup(description);
	msg->pdu.choice.dsm.dsop.choice.contextInfo.description->size = length;

	return DNDS_success;
}

int ContextInfo_get_description(DNDSMessage_t *msg, char **description, size_t *length)
{
	if (msg == NULL || description == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	*description = msg->pdu.choice.dsm.dsop.choice.contextInfo.description->buf;
	*length = msg->pdu.choice.dsm.dsop.choice.contextInfo.description->size;

	return DNDS_success;
}

int ContextInfo_set_network(DNDSMessage_t *msg, char *network)
{
	if (msg == NULL || network == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.network.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dsm.dsop.choice.contextInfo.network.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, network, msg->pdu.choice.dsm.dsop.choice.contextInfo.network.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.network.size = sizeof(struct in_addr);

	return DNDS_success;
}

int ContextInfo_get_network(DNDSMessage_t *msg, char *network)
{
	if (msg == NULL || network == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dsm.dsop.choice.contextInfo.network.buf, network, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int ContextInfo_set_netmask(DNDSMessage_t *msg, char *netmask)
{
	if (msg == NULL || netmask == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.netmask.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dsm.dsop.choice.contextInfo.netmask.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, netmask, msg->pdu.choice.dsm.dsop.choice.contextInfo.netmask.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.netmask.size = sizeof(struct in_addr);

	return DNDS_success;
}

int ContextInfo_get_netmask(DNDSMessage_t *msg, char *netmask)
{
	if (msg == NULL || netmask == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dsm.dsop.choice.contextInfo.netmask.buf, netmask, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}


int ContextInfo_set_serverCert(DNDSMessage_t *msg, const char *serverCert, size_t length)
{
	if (msg == NULL || serverCert == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.serverCert.buf = strdup(serverCert);
	msg->pdu.choice.dsm.dsop.choice.contextInfo.serverCert.size = length;

	return DNDS_success;
}

int ContextInfo_get_serverCert(DNDSMessage_t *msg, char **serverCert, size_t *length)
{
	if (msg == NULL || serverCert == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	*serverCert = msg->pdu.choice.dsm.dsop.choice.contextInfo.serverCert.buf;
	*length = msg->pdu.choice.dsm.dsop.choice.contextInfo.serverCert.size;

	return DNDS_success;
}

int ContextInfo_set_serverPrivkey(DNDSMessage_t *msg, const char *serverPrivkey, size_t length)
{
	if (msg == NULL || serverPrivkey == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.serverPrivkey.buf = strdup(serverPrivkey);
	msg->pdu.choice.dsm.dsop.choice.contextInfo.serverPrivkey.size = length;

	return DNDS_success;
}

int ContextInfo_get_serverPrivkey(DNDSMessage_t *msg, char **serverPrivkey, size_t *length)
{
	if (msg == NULL || serverPrivkey == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	*serverPrivkey = msg->pdu.choice.dsm.dsop.choice.contextInfo.serverPrivkey.buf;
	*length = msg->pdu.choice.dsm.dsop.choice.contextInfo.serverPrivkey.size;

	return DNDS_success;
}

int ContextInfo_set_trustedCert(DNDSMessage_t *msg, const char *trustedCert, size_t length)
{
	if (msg == NULL || trustedCert == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.contextInfo.trustedCert.buf = strdup(trustedCert);
	msg->pdu.choice.dsm.dsop.choice.contextInfo.trustedCert.size = length;

	return DNDS_success;
}


int ContextInfo_get_trustedCert(DNDSMessage_t *msg, char **trustedCert, size_t *length)
{
	if (msg == NULL || trustedCert == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_contextInfo) {
		return DNDS_invalid_op;
	}

	*trustedCert = msg->pdu.choice.dsm.dsop.choice.contextInfo.trustedCert.buf;
	*length = msg->pdu.choice.dsm.dsop.choice.contextInfo.trustedCert.size;

	return DNDS_success;
}

// PeerConnectInfo
int PeerConnectInfo_set_certName(DNDSMessage_t *msg, char *name, size_t length)
{
	if (msg == NULL || name == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_peerConnectInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.certName.buf = strdup(name);
	msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.certName.size = length;

	return DNDS_success;
}

int PeerConnectInfo_get_certName(DNDSMessage_t *msg, char **name, size_t *length)
{
	if (msg == NULL || name == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_peerConnectInfo) {
		return DNDS_invalid_op;
	}

	*name = msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.certName.buf;
	*length = msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.certName.size;

	return DNDS_success;
}

int PeerConnectInfo_set_ipAddr(DNDSMessage_t *msg, char *ipAddress)
{
	if (msg == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_peerConnectInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.ipAddr.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.ipAddr.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipAddress, msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.ipAddr.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.ipAddr.size = sizeof(struct in_addr);

	return DNDS_success;
}

int PeerConnectInfo_get_ipAddr(DNDSMessage_t *msg, char *ipAddress)
{
	if (msg == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_peerConnectInfo) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.ipAddr.buf, ipAddress, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int PeerConnectInfo_set_state(DNDSMessage_t *msg, e_ConnectState state)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_peerConnectInfo) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.state = state;

	return DNDS_success;
}

int PeerConnectInfo_get_state(DNDSMessage_t *msg, e_ConnectState *state)
{
	if (msg == NULL || state == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_peerConnectInfo) {
		return DNDS_invalid_op;
	}

	*state = msg->pdu.choice.dsm.dsop.choice.peerConnectInfo.state;

	return DNDS_success;
}

// AddRequest
int AddRequest_set_objectType(DNDSMessage_t *msg, DNDSObject_PR objType, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_addRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.addRequest.present = objType;
	*object = &msg->pdu.choice.dsm.dsop.choice.addRequest;

	return DNDS_success;
}

int AddRequest_get_objectType(DNDSMessage_t *msg, DNDSObject_PR *objType)
{
	if (msg == NULL || objType == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_addRequest) {
		return DNDS_invalid_op;
	}

	*objType = msg->pdu.choice.dsm.dsop.choice.addRequest.present;

	return DNDS_success;
}

int AddRequest_get_object(DNDSMessage_t *msg, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_addRequest) {
		return DNDS_invalid_op;
	}

	*object = &msg->pdu.choice.dsm.dsop.choice.addRequest;

	return DNDS_success;
}

// AddResponse
int AddResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_addResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.addResponse = result;

	return DNDS_success;
}

int AddResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_addResponse) {
		return DNDS_invalid_op;
	}

	*result = msg->pdu.choice.dsm.dsop.choice.addResponse;

	return DNDS_success;
}

// AuthRequest
int AuthRequest_set_certName(DNDSMessage_t *msg, char *certName, size_t length)
{
	if (msg == NULL || certName == NULL) {
		return DNDS_invalid_param;
	}

	switch (msg->pdu.present) {
		case pdu_PR_dsm:

			if (msg->pdu.choice.dsm.dsop.present != dsop_PR_authRequest) {
				return DNDS_invalid_op;
			}

			msg->pdu.choice.dsm.dsop.choice.authRequest.certName.buf = strdup(certName);
			msg->pdu.choice.dsm.dsop.choice.authRequest.certName.size = length;
			break;

		case pdu_PR_dnm:

			if (msg->pdu.choice.dnm.dnop.present != dnop_PR_authRequest) {
				return DNDS_invalid_op;
			}

			msg->pdu.choice.dnm.dnop.choice.authRequest.certName.buf = strdup(certName);
			msg->pdu.choice.dnm.dnop.choice.authRequest.certName.size = length;
			break;

		default:
			return DNDS_invalid_pdu;
	}

	return DNDS_success;
}

int AuthRequest_get_certName(DNDSMessage_t *msg, char **certName, size_t *length)
{
	if (msg == NULL || certName == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	switch (msg->pdu.present) {
		case pdu_PR_dsm:

			if (msg->pdu.choice.dsm.dsop.present != dsop_PR_authRequest) {
				return DNDS_invalid_op;
			}

			*certName = msg->pdu.choice.dsm.dsop.choice.authRequest.certName.buf;
			*length = msg->pdu.choice.dsm.dsop.choice.authRequest.certName.size;
			break;

		case pdu_PR_dnm:

			if (msg->pdu.choice.dnm.dnop.present != dnop_PR_authRequest) {
				return DNDS_invalid_op;
			}

			*certName = msg->pdu.choice.dnm.dnop.choice.authRequest.certName.buf;
			*length = msg->pdu.choice.dnm.dnop.choice.authRequest.certName.size;
			break;

		default:
			return DNDS_invalid_op;
	}

	return DNDS_success;
}

// AuthResponse
int AuthResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	switch (msg->pdu.present) {
		case pdu_PR_dsm:

			if (msg->pdu.choice.dsm.dsop.present != dsop_PR_authResponse) {
				return DNDS_invalid_op;
			}

			msg->pdu.choice.dsm.dsop.choice.authResponse = result;
			break;

		case pdu_PR_dnm:

			if (msg->pdu.choice.dnm.dnop.present != dnop_PR_authResponse) {
				return DNDS_invalid_op;
			}

			msg->pdu.choice.dnm.dnop.choice.authResponse = result;
			break;

		default:
			return DNDS_invalid_pdu;
	}

	return DNDS_success;
}

int AuthResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	switch (msg->pdu.present) {
		case pdu_PR_dsm:

			if (msg->pdu.choice.dsm.dsop.present != dsop_PR_authResponse) {
				return DNDS_invalid_op;
			}

			*result = msg->pdu.choice.dsm.dsop.choice.authResponse;
			break;

		case pdu_PR_dnm:

			if (msg->pdu.choice.dnm.dnop.present != dnop_PR_authResponse) {
				return DNDS_invalid_op;
			}

			*result = msg->pdu.choice.dnm.dnop.choice.authResponse;
			break;

		default:
			return DNDS_invalid_pdu;
	}

	return DNDS_success;
}
// DelRequest
int DelRequest_set_objectType(DNDSMessage_t *msg, DNDSObject_PR objType, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_delRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.delRequest.present = objType;
	*object = &msg->pdu.choice.dsm.dsop.choice.delRequest;

	return DNDS_success;
}

int DelRequest_get_objectType(DNDSMessage_t *msg, DNDSObject_PR *objType)
{
	if (msg == NULL || objType == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_delRequest) {
		return DNDS_invalid_op;
	}

	*objType = msg->pdu.choice.dsm.dsop.choice.delRequest.present;

	return DNDS_success;
}

int DelRequest_get_object(DNDSMessage_t *msg, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_delRequest) {
		return DNDS_invalid_op;
	}

	*object = &msg->pdu.choice.dsm.dsop.choice.addRequest;

	return DNDS_success;
}

// DelResponse
int DelResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_delResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.delResponse = result;

	return DNDS_success;
}

int DelResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_delResponse) {
		return DNDS_invalid_op;
	}

	*result = msg->pdu.choice.dsm.dsop.choice.delResponse;

	return DNDS_success;
}
// ModifyRequest
int ModifyRequest_set_objectType(DNDSMessage_t *msg, DNDSObject_PR objType, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_modifyRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.modifyRequest.present = objType;
	*object = &msg->pdu.choice.dsm.dsop.choice.modifyRequest;

	return DNDS_success;
}

int ModifyRequest_get_objectType(DNDSMessage_t *msg, DNDSObject_PR *objType)
{
	if (msg == NULL || objType == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_modifyRequest) {
		return DNDS_invalid_op;
	}

	*objType = msg->pdu.choice.dsm.dsop.choice.modifyRequest.present;

	return DNDS_success;
}

int ModifyRequest_get_object(DNDSMessage_t *msg, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_modifyRequest) {
		return DNDS_invalid_op;
	}

	*object = &msg->pdu.choice.dsm.dsop.choice.modifyRequest;

	return DNDS_success;
}

// ModifyResponse
int ModifyResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_modifyResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.modifyResponse = result;

	return DNDS_success;
}

int ModifyResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_modifyResponse) {
		return DNDS_invalid_op;
	}

	*result = msg->pdu.choice.dsm.dsop.choice.modifyResponse;

	return DNDS_success;
}

// NetinfoRequest
int NetinfoRequest_set_ipLocal(DNDSMessage_t *msg, char *ipLocal)
{
	if (msg == NULL || ipLocal == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoRequest.ipLocal.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dnm.dnop.choice.netinfoRequest.ipLocal.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipLocal, msg->pdu.choice.dnm.dnop.choice.netinfoRequest.ipLocal.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoRequest.ipLocal.size = sizeof(struct in_addr);

	return DNDS_success;
 }

int NetinfoRequest_get_ipLocal(DNDSMessage_t *msg, char *ipLocal)
{
	if (msg == NULL || ipLocal == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoRequest) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dnm.dnop.choice.netinfoRequest.ipLocal.buf, ipLocal, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int NetinfoRequest_set_macAddr(DNDSMessage_t *msg, uint8_t *macAddr)
{
	if (msg == NULL || macAddr == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoRequest.macAddr.buf = (uint8_t *)calloc(1, ETHER_ADDR_LEN);
	if (msg->pdu.choice.dnm.dnop.choice.netinfoRequest.macAddr.buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(msg->pdu.choice.dnm.dnop.choice.netinfoRequest.macAddr.buf, macAddr, ETHER_ADDR_LEN);
	msg->pdu.choice.dnm.dnop.choice.netinfoRequest.macAddr.size = ETHER_ADDR_LEN;

	return DNDS_success;
}

int NetinfoRequest_get_macAddr(DNDSMessage_t *msg, uint8_t *macAddr)
{
	if (msg == NULL || macAddr == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoRequest) {
		return DNDS_invalid_op;
	}

	memmove(macAddr, msg->pdu.choice.dnm.dnop.choice.netinfoRequest.macAddr.buf, ETHER_ADDR_LEN);

	return DNDS_success;
}

// NetinfoResponse
int NetinfoResponse_set_ipAddress(DNDSMessage_t *msg, char *ipAddress)
{
	if (msg == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoResponse.ipAddress.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dnm.dnop.choice.netinfoResponse.ipAddress.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipAddress, msg->pdu.choice.dnm.dnop.choice.netinfoResponse.ipAddress.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoResponse.ipAddress.size = sizeof(struct in_addr);

	return DNDS_success;
}

int NetinfoResponse_get_ipAddress(DNDSMessage_t *msg, char *ipAddress)
{
	if (msg == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoResponse) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dnm.dnop.choice.netinfoResponse.ipAddress.buf, ipAddress, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int NetinfoResponse_set_netmask(DNDSMessage_t *msg, char *netmask)
{
	if (msg == NULL || netmask == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoResponse.netmask.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dnm.dnop.choice.netinfoResponse.netmask.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, netmask, msg->pdu.choice.dnm.dnop.choice.netinfoResponse.netmask.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoResponse.netmask.size = sizeof(struct in_addr);

	return DNDS_success;
}

int NetinfoResponse_get_netmask(DNDSMessage_t *msg, char *netmask)
{
	if (msg == NULL || netmask == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoResponse) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dnm.dnop.choice.netinfoResponse.netmask.buf, netmask, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int NetinfoResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.netinfoResponse.result = result;

	return DNDS_success;
}

int NetinfoResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_netinfoResponse) {
		return DNDS_invalid_op;
	}

	*result = msg->pdu.choice.dnm.dnop.choice.netinfoResponse.result;

	return DNDS_success;
}

// P2pRequest
int P2pRequest_set_macAddrDst(DNDSMessage_t *msg, uint8_t *macAddrDst)
{
	if (msg == NULL || macAddrDst == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pRequest.macAddrDst.buf = (uint8_t *)calloc(1, ETHER_ADDR_LEN);
	if (msg->pdu.choice.dnm.dnop.choice.p2pRequest.macAddrDst.buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(msg->pdu.choice.dnm.dnop.choice.p2pRequest.macAddrDst.buf, macAddrDst, ETHER_ADDR_LEN);
	msg->pdu.choice.dnm.dnop.choice.p2pRequest.macAddrDst.size = ETHER_ADDR_LEN;

	return DNDS_success;
}

int P2pRequest_get_macAddrDst(DNDSMessage_t *msg, uint8_t *macAddrDst)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	memmove(macAddrDst, msg->pdu.choice.dnm.dnop.choice.p2pRequest.macAddrDst.buf, ETHER_ADDR_LEN);

	return DNDS_success;
}

int P2pRequest_set_ipAddrDst(DNDSMessage_t *msg, char *ipAddrDst)
{
	if (msg == NULL || ipAddrDst == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pRequest.ipAddrDst.buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (msg->pdu.choice.dnm.dnop.choice.p2pRequest.ipAddrDst.buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipAddrDst, msg->pdu.choice.dnm.dnop.choice.p2pRequest.ipAddrDst.buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pRequest.ipAddrDst.size = sizeof(struct in_addr);

	return DNDS_success;
}

int P2pRequest_get_ipAddrDst(DNDSMessage_t *msg, char *ipAddrDst)
{
	if (msg == NULL || ipAddrDst == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, msg->pdu.choice.dnm.dnop.choice.p2pRequest.ipAddrDst.buf, ipAddrDst, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int P2pRequest_set_port(DNDSMessage_t *msg, uint32_t port)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pRequest.port = port;

	return DNDS_success;
}

int P2pRequest_get_port(DNDSMessage_t *msg, uint32_t *port)
{
	if (msg == NULL || port == NULL) {
		return DNDS_invalid_param;
	}

	*port = msg->pdu.choice.dnm.dnop.choice.p2pRequest.port;

	return DNDS_success;
}

int P2pRequest_set_side(DNDSMessage_t *msg, e_P2pSide side)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pRequest.side = side;

	return DNDS_success;
}

int P2pRequest_get_side(DNDSMessage_t *msg, e_P2pSide *side)
{
	if (msg == NULL || side == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pRequest) {
		return DNDS_invalid_op;
	}

	*side = msg->pdu.choice.dnm.dnop.choice.p2pRequest.side;

	return DNDS_success;
}

// P2pResponse
int P2pResponse_set_macAddrDst(DNDSMessage_t *msg, uint8_t *macAddrDst)
{
	if (msg == NULL || macAddrDst == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pResponse.macAddrDst.buf = (uint8_t *)calloc(1, ETHER_ADDR_LEN);
	if (msg->pdu.choice.dnm.dnop.choice.p2pResponse.macAddrDst.buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(msg->pdu.choice.dnm.dnop.choice.p2pResponse.macAddrDst.buf, macAddrDst, ETHER_ADDR_LEN);
	msg->pdu.choice.dnm.dnop.choice.p2pResponse.macAddrDst.size = ETHER_ADDR_LEN;

	return DNDS_success;
}

int P2pResponse_get_macAddrDst(DNDSMessage_t *msg, uint8_t *macAddrDst)
{
	if (msg == NULL || macAddrDst == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pResponse) {
		return DNDS_invalid_op;
	}

	memmove(macAddrDst, msg->pdu.choice.dnm.dnop.choice.p2pResponse.macAddrDst.buf, ETHER_ADDR_LEN);

	return DNDS_success;
}

int P2pResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dnm.dnop.choice.p2pResponse.result = result;

	return DNDS_success;
}

int P2pResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dnm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dnm.dnop.present != dnop_PR_p2pResponse) {
		return DNDS_invalid_op;
	}

	*result = msg->pdu.choice.dnm.dnop.choice.p2pResponse.result;

	return DNDS_success;
}
// SearchRequest
int SearchRequest_set_objectType(DNDSMessage_t *msg, DNDSObject_PR objType, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchRequest) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.searchRequest.present = objType;
	*object = &msg->pdu.choice.dsm.dsop.choice.searchRequest;

	return DNDS_success;
}

int SearchRequest_get_objectType(DNDSMessage_t *msg, DNDSObject_PR *objType)
{
	if (msg == NULL || objType == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchRequest) {
		return DNDS_invalid_op;
	}

	*objType = msg->pdu.choice.dsm.dsop.choice.searchRequest.present;

	return DNDS_success;
}

int SearchRequest_get_object(DNDSMessage_t *msg, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchRequest) {
		return DNDS_invalid_op;
	}

	*object = &msg->pdu.choice.dsm.dsop.choice.searchRequest;

	return DNDS_success;
}

// SearchResponse
int SearchResponse_set_result(DNDSMessage_t *msg, e_DNDSResult result)
{
	if (msg == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchResponse) {
		return DNDS_invalid_op;
	}

	msg->pdu.choice.dsm.dsop.choice.searchResponse.dndsResult = result;

	return DNDS_success;
}

int SearchResponse_get_result(DNDSMessage_t *msg, e_DNDSResult *result)
{
	if (msg == NULL || result == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchResponse) {
		return DNDS_invalid_op;
	}

	*result = msg->pdu.choice.dsm.dsop.choice.searchResponse.dndsResult;

	return DNDS_success;
}
int SearchResponse_add_object(DNDSMessage_t *msg, DNDSObject_t *object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchResponse) {
		return DNDS_invalid_op;
	}

	asn_set_add(&msg->pdu.choice.dsm.dsop.choice.searchResponse.objects.list, object);

	return DNDS_success;
}

int SearchResponse_get_object(DNDSMessage_t *msg, DNDSObject_t **object)
{
	if (msg == NULL || object == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchResponse) {
		return DNDS_invalid_op;
	}

	int count = msg->pdu.choice.dsm.dsop.choice.searchResponse.objects.list.count;
	if (count > 0) {

		*object = msg->pdu.choice.dsm.dsop.choice.searchResponse.objects.list.array[count-1];
		asn_set_del(&msg->pdu.choice.dsm.dsop.choice.searchResponse.objects.list, count-1, 0);
	}
	else {
		return DNDS_value_not_present;
	}

	return DNDS_success;
}

int SearchResponse_get_object_count(DNDSMessage_t *msg, uint32_t *count)
{
	if (msg == NULL || count == NULL) {
		return DNDS_invalid_param;
	}

	if (msg->pdu.present != pdu_PR_dsm) {
		return DNDS_invalid_pdu;
	}

	if (msg->pdu.choice.dsm.dsop.present != dsop_PR_searchResponse) {
		return DNDS_invalid_op;
	}

	*count = msg->pdu.choice.dsm.dsop.choice.searchResponse.objects.list.count;

	return DNDS_success;
}

// terminateRequest -- need nothing

// DNDS Objects
int DNDSObject_new(DNDSObject_t **object)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	*object = calloc(1, sizeof(DNDSObject_t));

	if (*object == NULL) {
		return DNDS_alloc_failed;
	}

	return DNDS_success;
}

// Acl
int Acl_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_acl) {
		return DNDS_invalid_object_type;
	}

	object->choice.acl.id = id;

	return DNDS_success;
}

int Acl_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_acl) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.acl.id;

	return DNDS_success;
}

int Acl_set_contextId(DNDSObject_t *object, uint32_t contextId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_acl) {
		return DNDS_invalid_object_type;
	}

	object->choice.acl.contextId = contextId;

	return DNDS_success;
}

int Acl_get_contextId(DNDSObject_t *object, uint32_t *contextId)
{
	if (object == NULL || contextId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_acl) {
		return DNDS_invalid_object_type;
	}

	*contextId = object->choice.acl.contextId;

	return DNDS_success;
}

int Acl_set_description(DNDSObject_t *object, char *description, size_t length)
{
	if (object == NULL || description == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_acl) {
		return DNDS_invalid_object_type;
	}

	object->choice.acl.description = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.acl.description == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.acl.description->buf = strdup(description);
	object->choice.acl.description->size = length;

	return DNDS_success;
}

int Acl_get_description(DNDSObject_t *object, char **description, size_t *length)
{
	if (object == NULL || description == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_acl) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.acl.description == NULL) {
		return DNDS_value_not_present;
	}

	*description = object->choice.acl.description->buf;
	*length = object->choice.acl.description->size;

	return DNDS_success;
}

// AclGroup
int AclGroup_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	object->choice.aclgroup.id = id;

	return DNDS_success;
}

int AclGroup_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.aclgroup.id;

	return DNDS_success;
}

int AclGroup_set_contextId(DNDSObject_t *object, uint32_t contextId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	object->choice.aclgroup.contextId = contextId;

	return DNDS_success;
}

int AclGroup_get_contextId(DNDSObject_t *object, uint32_t *contextId)
{
	if (object == NULL || contextId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	*contextId = object->choice.aclgroup.contextId;

	return DNDS_success;
}

int AclGroup_set_name(DNDSObject_t *object, char *name, size_t length)
{
	if (object == NULL || name == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	object->choice.aclgroup.name = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.aclgroup.name == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.aclgroup.name->buf = strdup(name);
	object->choice.aclgroup.name->size = length;

	return DNDS_success;
}

int AclGroup_get_name(DNDSObject_t *object, char **name, size_t *length)
{
	if (object == NULL || name == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.aclgroup.name == NULL) {
		return DNDS_value_not_present;
	}

	*name = object->choice.aclgroup.name->buf;
	*length = object->choice.aclgroup.name->size;

	return DNDS_success;
}

int AclGroup_set_description(DNDSObject_t *object, char *description, size_t length)
{
	if (object == NULL || description == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	object->choice.aclgroup.description = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.aclgroup.description == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.aclgroup.description->buf = strdup(description);
	object->choice.aclgroup.description->size = length;

	return DNDS_success;
}

int AclGroup_get_description(DNDSObject_t *object, char **description, size_t *length)
{
	if (object == NULL || description == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_aclgroup) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.aclgroup.description == NULL) {
		return DNDS_value_not_present;
	}

	*description = object->choice.aclgroup.description->buf;
	*length = object->choice.aclgroup.description->size;

	return DNDS_success;
}

// IpPool
int IpPool_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	object->choice.ippool.id = id;

	return DNDS_success;
}

int IpPool_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.ippool.id;

	return DNDS_success;
}

int IpPool_set_ipLocal(DNDSObject_t *object, char *ipLocal)
{
	if (object == NULL || ipLocal == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	object->choice.ippool.ipLocal = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.ippool.ipLocal == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.ippool.ipLocal->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.ippool.ipLocal == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipLocal, object->choice.ippool.ipLocal->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.ippool.ipLocal->size = sizeof(struct in_addr);

	return DNDS_success;
}

int IpPool_get_ipLocal(DNDSObject_t *object, char *ipLocal)
{
	if (object == NULL || ipLocal == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.ippool.ipLocal == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.ippool.ipLocal->buf, ipLocal, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int IpPool_set_ipBegin(DNDSObject_t *object, char *ipBegin)
{
	if (object == NULL || ipBegin == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	object->choice.ippool.ipBegin = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.ippool.ipBegin == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.ippool.ipBegin->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.ippool.ipBegin->buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipBegin, object->choice.ippool.ipBegin->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.ippool.ipBegin->size = sizeof(struct in_addr);

	return DNDS_success;
}

int IpPool_get_ipBegin(DNDSObject_t *object, char *ipBegin)
{
	if (object == NULL || ipBegin == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.ippool.ipBegin == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.ippool.ipBegin->buf, ipBegin, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int IpPool_set_ipEnd(DNDSObject_t *object, char *ipEnd)
{
	if (object == NULL || ipEnd == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	object->choice.ippool.ipEnd = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.ippool.ipEnd == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.ippool.ipEnd->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.ippool.ipEnd->buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipEnd, object->choice.ippool.ipEnd->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.ippool.ipEnd->size = sizeof(struct in_addr);

	return DNDS_success;
}

int IpPool_get_ipEnd(DNDSObject_t *object, char *ipEnd)
{
	if (object == NULL || ipEnd == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.ippool.ipEnd == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.ippool.ipEnd->buf, ipEnd, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int IpPool_set_netmask(DNDSObject_t *object, char *netmask)
{
	if (object == NULL || netmask == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	object->choice.ippool.netmask = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.ippool.netmask == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.ippool.netmask->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.ippool.netmask->buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, netmask, object->choice.ippool.netmask->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.ippool.netmask->size = sizeof(struct in_addr);

	return DNDS_success;
}

int IpPool_get_netmask(DNDSObject_t *object, char *netmask)
{
	if (object == NULL || netmask == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_ippool) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.ippool.netmask == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.ippool.netmask->buf, netmask, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

// Context
int Context_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.id = id;

	return DNDS_success;
}

int Context_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.context.id;

	return DNDS_success;
}

int Context_set_ippoolId(DNDSObject_t *object, uint32_t ippoolId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.ippoolId = ippoolId;

	return DNDS_success;
}

int Context_get_ippoolId(DNDSObject_t *object, uint32_t *ippoolId)
{
	if (object == NULL || ippoolId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	*ippoolId = object->choice.context.ippoolId;

	return DNDS_success;
}

int Context_set_dnsZone(DNDSObject_t *object, char *dnsZone, size_t length)
{
	if (object == NULL || dnsZone == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.dnsZone = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.context.dnsZone == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.context.dnsZone->buf = strdup(dnsZone);
	object->choice.context.dnsZone->size = length;

	return DNDS_success;
}

int Context_get_dnsZone(DNDSObject_t *object, char **dnsZone, size_t *length)
{
	if (object == NULL || dnsZone == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.context.dnsZone == NULL) {
		return DNDS_value_not_present;
	}

	*dnsZone = object->choice.context.dnsZone->buf;
	*length = object->choice.context.dnsZone->size;

	return DNDS_success;
}

int Context_set_dnsSerial(DNDSObject_t *object, uint32_t dnsSerial)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.dnsSerial = (unsigned long *)calloc(1, sizeof(unsigned long));
	if (object->choice.context.dnsSerial == NULL) {
		return DNDS_alloc_failed;
	}

	*object->choice.context.dnsSerial = dnsSerial;

	return DNDS_success;
}

int Context_get_dnsSerial(DNDSObject_t *object, uint32_t *dnsSerial)
{
	if (object == NULL || dnsSerial == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.context.dnsSerial == NULL) {
		return DNDS_value_not_present;
	}

	*dnsSerial = *object->choice.context.dnsSerial;

	return DNDS_success;
}

int Context_set_vhost(DNDSObject_t *object, char *vhost, size_t length)
{
	if (object == NULL || vhost == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.vhost = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.context.vhost == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.context.vhost->buf = strdup(vhost);
	object->choice.context.vhost->size = length;

	return DNDS_success;
}

int Context_get_vhost(DNDSObject_t *object, char **vhost, size_t *length)
{
	if (object == NULL || vhost == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.context.vhost == NULL) {
		return DNDS_value_not_present;
	}

	*vhost = object->choice.context.vhost->buf;
	*length = object->choice.context.vhost->size;

	return DNDS_success;
}

int Context_set_certificate(DNDSObject_t *object, char *certificate, size_t length)
{
	if (object == NULL || certificate == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.certificate = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.context.certificate == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.context.certificate->buf = strdup(certificate);
	object->choice.context.certificate->size = length;

	return DNDS_success;
}

int Context_get_certificate(DNDSObject_t *object, char **certificate, size_t *length)
{
	if (object == NULL || certificate == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.context.certificateKey == NULL) {
		return DNDS_value_not_present;
	}

	*certificate = object->choice.context.certificate->buf;
	*length = object->choice.context.certificate->size;

	return DNDS_success;
}

int Context_set_certificateKey(DNDSObject_t *object, uint8_t *certificateKey, size_t length)
{
	if (object == NULL || certificateKey == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.certificateKey = (BIT_STRING_t *)calloc(1, sizeof(BIT_STRING_t));
	if (object->choice.context.certificateKey == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.context.certificateKey->buf = (uint8_t *)calloc(1, length);
	if (object->choice.context.certificateKey->buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(object->choice.context.certificateKey->buf, certificateKey, length);
	object->choice.context.certificateKey->size = length;

	return DNDS_success;
}

int Context_get_certificateKey(DNDSObject_t *object, uint8_t **certificateKey, size_t *length)
{
	if (object == NULL || certificateKey == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.context.certificateKey == NULL) {
		return DNDS_value_not_present;
	}

	*certificateKey = object->choice.context.certificateKey->buf;
	*length = object->choice.context.certificateKey->size;

	return DNDS_success;
}

int Context_set_trustList()
{
}

int Context_set_revokeList()
{
}

int Context_set_description(DNDSObject_t *object, char *description, size_t length)
{
	if (object == NULL || description == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	object->choice.context.description = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.context.description == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.context.description->buf = strdup(description);
	object->choice.context.description->size = length;

	return DNDS_success;
}

int Context_get_description(DNDSObject_t *object, char **description, size_t *length)
{
	if (object == NULL || description == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_context) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.context.description == NULL) {
		return DNDS_value_not_present;
	}

	*description = object->choice.context.description->buf;
	*length = object->choice.context.description->size;

	return DNDS_success;
}

// Host
int Host_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.id = id;

	return DNDS_success;
}

int Host_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.host.id;

	return DNDS_success;
}

int Host_set_contextId(DNDSObject_t *object, uint32_t contextId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.contextId = contextId;

	return DNDS_success;
}

int Host_get_contextId(DNDSObject_t *object, uint32_t *contextId)
{
	if (object == NULL || contextId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	*contextId = object->choice.host.contextId;

	return DNDS_success;
}

int Host_set_peerId(DNDSObject_t *object, uint32_t peerId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.peerId = peerId;

	return DNDS_success;
}

int Host_get_peerId(DNDSObject_t *object, uint32_t *peerId)
{
	if (object == NULL || peerId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	*peerId = object->choice.host.peerId;

	return DNDS_success;
}

int Host_set_name(DNDSObject_t *object, char *name, size_t length)
{
	if (object == NULL || name == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.name = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.host.name == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.host.name->buf = strdup(name);
	object->choice.host.name->size = length;

	return DNDS_success;
}

int Host_get_name(DNDSObject_t *object, char **name, size_t *length)
{
	if (object == NULL || name == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.host.name == NULL) {
		return DNDS_value_not_present;
	}

	*name = object->choice.host.name->buf;
	*length = object->choice.host.name->size;

	return DNDS_success;
}

int Host_set_macAddress(DNDSObject_t *object, uint8_t *macAddress)
{
	if (object == NULL || macAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.macAddress = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.host.macAddress == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.host.macAddress->buf = (uint8_t *)calloc(1, ETHER_ADDR_LEN);
	if (object->choice.host.macAddress->buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(object->choice.host.macAddress->buf, macAddress, ETHER_ADDR_LEN);
	object->choice.host.macAddress->size = ETHER_ADDR_LEN;

	return DNDS_success;
}

int Host_get_macAddress(DNDSObject_t *object, uint8_t *macAddress)
{
	if (object == NULL || macAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.host.macAddress == NULL) {
		return DNDS_value_not_present;
	}

	memmove(macAddress, object->choice.host.macAddress->buf, ETHER_ADDR_LEN);

	return DNDS_success;
}

int Host_set_ipAddress(DNDSObject_t *object, char *ipAddress)
{
	if (object == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.ipAddress = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.host.ipAddress == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.host.ipAddress->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.host.ipAddress->buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipAddress, object->choice.host.ipAddress->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.host.ipAddress->size = sizeof(struct in_addr);

	return DNDS_success;
}

int Host_get_ipAddress(DNDSObject_t *object, char *ipAddress)
{
	if (object == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.host.ipAddress == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.host.ipAddress->buf, ipAddress, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int Host_set_status(DNDSObject_t *object, uint8_t status)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	object->choice.host.status = (long *)calloc(1, sizeof(long));
	if (object->choice.host.status == NULL) {
		return DNDS_alloc_failed;
	}

	*object->choice.host.status = status;

	return DNDS_success;
}

int Host_get_status(DNDSObject_t *object, uint8_t *status)
{
	if (object == NULL || status == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_host) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.host.status == NULL) {
		return DNDS_value_not_present;
	}

	*status = *object->choice.host.status;

	return DNDS_success;
}

// Node
int Node_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	object->choice.node.id = id;

	return DNDS_success;
}

int Node_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.node.id;

	return DNDS_success;
}

int Node_set_name(DNDSObject_t *object, char *name, size_t length)
{
	if (object == NULL || name == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	object->choice.node.name = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.node.name == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.node.name->buf = strdup(name);
	object->choice.node.name->size = length;

	return DNDS_success;
}

int Node_get_name(DNDSObject_t *object, char **name, size_t *length)
{
	if (object == NULL || name == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.node.name == NULL) {
		return DNDS_value_not_present;
	}

	*name = object->choice.node.name->buf;
	*length = object->choice.node.name->size;

	return DNDS_success;
}

int Node_set_ipAddress(DNDSObject_t *object, char *ipAddress)
{
	if (object == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	object->choice.node.ipAddress = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.node.ipAddress == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.node.ipAddress->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.node.ipAddress->buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipAddress, object->choice.node.ipAddress->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.node.ipAddress->size = sizeof(struct in_addr);

	return DNDS_success;
}

int Node_get_ipAddress(DNDSObject_t *object, char *ipAddress)
{
	if (object == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.node.ipAddress == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.node.ipAddress->buf, ipAddress, INET_ADDRSTRLEN);
	if (ret == NULL) {
		DNDS_conversion_failed;
	}

	return DNDS_success;
}

int Node_set_certificate(DNDSObject_t *object, char *certificate, size_t length)
{
	if (object == NULL || certificate == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	object->choice.node.certificate = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.node.certificate == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.node.certificate->buf = strdup(certificate);
	object->choice.node.certificate->size = length;

	return DNDS_success;
}

int Node_get_certificate(DNDSObject_t *object, char **certificate, size_t *length)
{
	if (object == NULL || certificate == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.node.certificate == NULL) {
		return DNDS_value_not_present;
	}

	*certificate = object->choice.node.certificate->buf;
	*length = object->choice.node.certificate->size;

	return DNDS_success;
}

int Node_set_certificateKey(DNDSObject_t *object, uint8_t *certificateKey, size_t length)
{
	if (object == NULL || certificateKey == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	object->choice.node.certificateKey = (BIT_STRING_t *)calloc(1, sizeof(BIT_STRING_t));
	if (object->choice.node.certificateKey == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.node.certificateKey->buf = (uint8_t *)calloc(1, length);
	if (object->choice.node.certificateKey->buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(object->choice.node.certificateKey->buf, certificateKey, length);
	object->choice.node.certificateKey->size = length;

	return DNDS_success;
}

int Node_get_certificateKey(DNDSObject_t *object, uint8_t **certificateKey, size_t *length)
{
	if (object == NULL || certificateKey == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.node.certificateKey == NULL) {
		return DNDS_value_not_present;
	}

	*certificateKey = object->choice.node.certificateKey->buf;
	*length = object->choice.node.certificateKey->size;

	return DNDS_success;
}

int Node_set_permission()
{
}

int Node_set_status(DNDSObject_t *object, uint8_t status)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	object->choice.node.status = (long *)calloc(1, sizeof(long));
	*object->choice.node.status = status;

	return DNDS_success;
}

int Node_get_status(DNDSObject_t *object, uint8_t *status)
{
	if (object == NULL || status == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_node) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.node.status == NULL) {
		return DNDS_value_not_present;
	}

	*status = *object->choice.node.status;

	return DNDS_success;
}

// Permission
int Permission_set_id()
{
}

int Permission_set_name()
{
}

int Permission_set_matrix()
{
}

// Peer
int Peer_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	object->choice.peer.id = id;

	return DNDS_success;
}

int Peer_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.peer.id;

	return DNDS_success;
}

int Peer_set_contextId(DNDSObject_t *object, uint32_t contextId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	object->choice.peer.contextId = contextId;

	return DNDS_success;
}

int Peer_get_contextId(DNDSObject_t *object, uint32_t *contextId)
{
	if (object == NULL || contextId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	*contextId = object->choice.peer.contextId;

	return DNDS_success;
}

int Peer_set_ipAddress(DNDSObject_t *object, char *ipAddress)
{
	if (object == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	object->choice.peer.ipAddress = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
	if (object->choice.peer.ipAddress == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.peer.ipAddress->buf = (uint8_t *)calloc(1, sizeof(struct in_addr));
	if (object->choice.peer.ipAddress->buf == NULL) {
		return DNDS_alloc_failed;
	}

	int ret;
	ret = inet_pton(AF_INET, ipAddress, object->choice.peer.ipAddress->buf);
	if (ret != 1) {
		return DNDS_conversion_failed;
	}

	object->choice.peer.ipAddress->size = sizeof(struct in_addr);

	return DNDS_success;
}

int Peer_get_ipAddress(DNDSObject_t *object, char *ipAddress)
{
	if (object == NULL || ipAddress == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.peer.ipAddress == NULL) {
		return DNDS_value_not_present;
	}

	const char *ret;
	ret = inet_ntop(AF_INET, object->choice.peer.ipAddress->buf, ipAddress, INET_ADDRSTRLEN);
	if (ret == NULL) {
		return DNDS_conversion_failed;
	}

	return DNDS_success;
}

int Peer_set_certificate(DNDSObject_t *object, char *certificate, size_t length)
{
	if (object == NULL || certificate == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	object->choice.peer.certificate = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.peer.certificate == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.peer.certificate->buf = strdup(certificate);
	object->choice.peer.certificate->size = length;

	return DNDS_success;
}

int Peer_get_certificate(DNDSObject_t *object, char **certificate, size_t *length)
{
	if (object == NULL || certificate == NULL || length == length) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.peer.certificate == NULL) {
		return DNDS_value_not_present;
	}

	*certificate = object->choice.peer.certificate->buf;
	*length = object->choice.peer.certificate->size;

	return DNDS_success;
}

int Peer_set_certificateKey(DNDSObject_t *object, uint8_t *certificateKey, size_t length)
{
	if (object == NULL || certificateKey == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	object->choice.peer.certificateKey = (BIT_STRING_t *)calloc(1, sizeof(BIT_STRING_t));
	if (object->choice.peer.certificateKey == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.peer.certificateKey->buf = (uint8_t *)calloc(1, length);
	if (object->choice.peer.certificateKey->buf == NULL) {
		return DNDS_alloc_failed;
	}

	memmove(object->choice.peer.certificateKey->buf, certificateKey, length);
	object->choice.peer.certificateKey->size = length;

	return DNDS_success;
}

int Peer_get_certificateKey(DNDSObject_t *object, uint8_t **certificateKey, size_t *length)
{
	if (object == NULL || certificateKey == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.peer.certificateKey == NULL) {
		return	DNDS_value_not_present;
	}

	*certificateKey = object->choice.peer.certificateKey->buf;
	*length = object->choice.peer.certificateKey->size;

	return DNDS_success;
}

int Peer_set_status(DNDSObject_t *object, uint8_t status)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	object->choice.peer.status = (long *)calloc(1, sizeof(long));
	if (object->choice.peer.status == NULL) {
		return DNDS_alloc_failed;
	}

	*object->choice.peer.status = status;

	return DNDS_success;
}

int Peer_get_status(DNDSObject_t *object, uint8_t *status)
{
	if (object == NULL || status == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_peer) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.peer.status == NULL) {
		return DNDS_value_not_present;
	}

	*status = *object->choice.peer.status;

	return DNDS_success;
}

// User
int User_set_id(DNDSObject_t *object, uint32_t id)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.id = id;

	return DNDS_success;
}

int User_get_id(DNDSObject_t *object, uint32_t *id)
{
	if (object == NULL || id == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	*id = object->choice.user.id;

	return DNDS_success;
}

int User_set_contextId(DNDSObject_t *object, uint32_t contextId)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.contextId = contextId;

	return DNDS_success;
}

int User_get_contextId(DNDSObject_t *object, uint32_t *contextId)
{
	if (object == NULL || contextId == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	*contextId = object->choice.user.contextId;

	return DNDS_success;
}

int User_set_name(DNDSObject_t *object, char *name, size_t length)
{
	if (object == NULL || name == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.name = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.user.name == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.user.name->buf = strdup(name);
	object->choice.user.name->size = length;

	return DNDS_success;
}

int User_get_name(DNDSObject_t *object, char **name, size_t *length)
{
	if (object == NULL || name == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.name == NULL) {
		return DNDS_value_not_present;
	}

	*name = object->choice.user.name->buf;
	*length = object->choice.user.name->size;

	return DNDS_success;
}

int User_set_password(DNDSObject_t *object, char *password, size_t length)
{
	if (object == NULL || password == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.password = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.user.password == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.user.password->buf = strdup(password);
	object->choice.user.password->size = length;

	return DNDS_success;
}

int User_get_password(DNDSObject_t *object, char **password, size_t *length)
{
	if (object == NULL || password == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.password == NULL) {
		return DNDS_value_not_present;
	}

	*password = object->choice.user.password->buf;
	*length = object->choice.user.password->size;

	return DNDS_success;
}

int User_set_firstname(DNDSObject_t *object, char *firstname, size_t length)
{
	if (object == NULL || firstname == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.firstname = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.user.firstname == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.user.firstname->buf = strdup(firstname);
	object->choice.user.firstname->size = length;

	return DNDS_success;
}

int User_get_firstname(DNDSObject_t *object, char **firstname, size_t *length)
{
	if (object == NULL || firstname == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.firstname == NULL) {
		return DNDS_value_not_present;
	}

	*firstname = object->choice.user.firstname->buf;
	*length = object->choice.user.firstname->size;

	return DNDS_success;
}

int User_set_lastname(DNDSObject_t *object, char *lastname, size_t length)
{
	if (object == NULL || lastname == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.lastname = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.user.lastname == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.user.lastname->buf = strdup(lastname);
	object->choice.user.lastname->size = length;

	return DNDS_success;
}

int User_get_lastname(DNDSObject_t *object, char **lastname, size_t *length)
{
	if (object == NULL || lastname == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.lastname == NULL) {
		return DNDS_value_not_present;
	}

	*lastname = object->choice.user.lastname->buf;
	*length = object->choice.user.lastname->size;

	return DNDS_success;
}

int User_set_email(DNDSObject_t *object, char *email, size_t length)
{
	if (object == NULL || email == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.email = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
	if (object->choice.user.email == NULL) {
		return DNDS_alloc_failed;
	}

	object->choice.user.email->buf = strdup(email);
	object->choice.user.email->size = length;

	return DNDS_success;
}

int User_get_email(DNDSObject_t *object, char **email, size_t *length)
{
	if (object == NULL || email == NULL || length == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.email == NULL) {
		return DNDS_value_not_present;
	}

	*email = object->choice.user.email->buf;
	*length = object->choice.user.email->size;

	return DNDS_success;
}

int User_set_role(DNDSObject_t *object, uint8_t role)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.role = (long *)calloc(1, sizeof(long));
	if (object->choice.user.role == NULL) {
		return DNDS_alloc_failed;
	}

	*object->choice.user.role = role;

	return DNDS_success;
}

int User_get_role(DNDSObject_t *object, uint8_t *role)
{
	if (object == NULL || role == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.role == NULL) {
		return DNDS_value_not_present;
	}

	*role = *object->choice.user.role;

	return DNDS_success;
}

int User_set_status(DNDSObject_t *object, uint8_t status)
{
	if (object == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	object->choice.user.status = (long *)calloc(1, sizeof(long));
	if (object->choice.user.status == NULL) {
		return DNDS_alloc_failed;
	}

	*object->choice.user.status = status;

	return DNDS_success;
}

int User_get_status(DNDSObject_t *object, uint8_t *status)
{
	if (object == NULL || status == NULL) {
		return DNDS_invalid_param;
	}

	if (object->present != DNDSObject_PR_user) {
		return DNDS_invalid_object_type;
	}

	if (object->choice.user.status == NULL) {
		return DNDS_value_not_present;
	}

	*status = *object->choice.user.status;

	return DNDS_success;
}

char *Topology_str(e_Topology topology)
{
	switch (topology) {
	case Topology_mesh:
		return "Mesh";
	case Topology_hubspoke:
		return "Hub and Spoke";
	case Topology_gateway:
		return "Gateway";
	}
	return "Unknown";
}

char *ConnectState_str(e_ConnectState state)
{
	switch (state) {
	case ConnectState_connected:
		return "Connected";
	case ConnectState_disconnected:
		return "Disconnected";
	}
	return "Unknown";
}

char *P2pSide_str(e_P2pSide side)
{
	switch (side) {
	case P2pSide_client:
		return "Client";
	case P2pSide_server:
		return "Server";
	}
	return "Unknown";
}

// DNDS API functions
char *DNDSResult_str(e_DNDSResult result)
{
	char *str = NULL;

	switch (result) {
		case DNDSResult_success:
			str = strdup("Success");
			break;

		case DNDSResult_operationError:
			str = strdup("Operation error");
			break;

		case DNDSResult_protocolError:
			str = strdup("Protocol error");
			break;

		case DNDSResult_noSuchObject:
			str = strdup("No such object");
			break;

		case DNDSResult_busy:
			str = strdup("Busy");
			break;

		case DNDSResult_secureStepUp:
			str = strdup("Secure step up");
			break;

		case DNDSResult_insufficientAccessRights:
			str = strdup("Insufficient access rights");
			break;
	}

	return str;

}
char *DNDS_strerror(DNDS_retcode_t retcode)
{
	char *strerror = NULL;

	switch (retcode) {
		case DNDS_success:
			strerror = strdup("Success");
			break;

		case DNDS_alloc_failed:
			strerror = strdup("Memory allocation failed");
			break;

		case DNDS_invalid_param:
			strerror = strdup("A parameter passed to the function is invalid");
			break;

		case DNDS_invalid_pdu:
			strerror = strdup("The PDU type is not set");
			break;

		case DNDS_invalid_op:
			strerror = strdup("The operation type is not set");

		case DNDS_invalid_object_type:
			strerror = strdup("The object type is not set");
			break;

		case DNDS_value_not_present:
			strerror = strdup("The value is not present");
			break;

		case DNDS_conversion_failed:
			strerror = strdup("Internal conversion failed");
			break;
	}

	return strerror;
}

// _printf functions usefull for debugging
void DNDSMessage_printf(DNDSMessage_t *msg)
{
	uint8_t channel;
	DNDSMessage_get_channel(msg, &channel);
	printf("DNDSMessage> channel: %i\n", channel);

	pdu_PR pdu;
	DNDSMessage_get_pdu(msg, &pdu);
	printf("DNDSMessage> pdu: %i\n", pdu);
}

void DNDSMessage_ethernet_printf(DNDSMessage_t *msg)
{
	uint8_t *frame;
	size_t length;

	DNDSMessage_get_ethernet(msg, &frame, &length);
	int i; for (i = 0; i < length; i++) { printf("%x", frame[i]); }; printf("\n");
}

void DSMessage_printf(DNDSMessage_t *msg)
{
	uint32_t seqNumber;
	DSMessage_get_seqNumber(msg, &seqNumber);
	printf("DSMessage> seqNumber: %i\n", seqNumber);

	uint32_t ackNumber;
	DSMessage_get_ackNumber(msg, &ackNumber);
	printf("DSMessage> ackNumber: %i\n", ackNumber);

	dsop_PR operation;
	DSMessage_get_operation(msg, &operation);
	printf("DSMessage> operation: %i\n", operation);
}

void DNMessage_printf(DNDSMessage_t *msg)
{
	uint32_t seqNumber;
	DNMessage_get_seqNumber(msg, &seqNumber);
	printf("DNMessage> seqNumber: %i\n", seqNumber);

	uint32_t ackNumber;
	DNMessage_get_ackNumber(msg, &ackNumber);
	printf("DNMessage> ackNumber: %i\n", ackNumber);

	dnop_PR operation;
	DNMessage_get_operation(msg, &operation);
	printf("DNMessage> operation: %i\n", operation);
}

void AddRequest_printf(DNDSMessage_t *msg)
{
	DNDSObject_PR objType;
	AddRequest_get_objectType(msg, &objType);
	printf("AddRequest> objType: %i\n", objType);
}

void AddResponse_printf(DNDSMessage_t *msg)
{
	e_DNDSResult result;
	AddResponse_get_result(msg, &result);
	printf("AddResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void ContextInfo_printf(DNDSMessage_t *msg)
{
	int ret = 0;
	size_t length;

	uint32_t id;
        ret = ContextInfo_get_id(msg, &id);
	printf("ContextInfo> id(%i): %d\n", ret,  id);

	e_Topology topology;
        ret = ContextInfo_get_topology(msg, &topology);
	printf("ContextInfo> topology(%i): %s\n", ret, Topology_str(topology));

	char *desc;
        ret = ContextInfo_get_description(msg, &desc, &length);
	printf("ContextInfo> description(%i): %s\n", ret, desc);

	char network[INET_ADDRSTRLEN];
        ret = ContextInfo_get_network(msg, network);
	printf("ContextInfo> network(%i): %s\n", ret, network);

	char netmask[INET_ADDRSTRLEN];
        ret = ContextInfo_get_netmask(msg, netmask);
	printf("ContextInfo> netmask(%i): %s\n", ret, netmask);

	char *serverCert;
        ret = ContextInfo_get_serverCert(msg, &serverCert, &length);
	printf("ContextInfo> serverCert(%i): %s\n", ret, serverCert);

	char *serverPrivkey;
        ret = ContextInfo_get_serverPrivkey(msg, &serverPrivkey, &length);
	printf("ContextInfo> serverPrivkey(%i): %s\n", ret, serverPrivkey);

	char *trustedCert;
        ret = ContextInfo_get_trustedCert(msg, &trustedCert, &length);
	printf("ContextInfo> trustedCert(%i): %s\n", ret, trustedCert);
}

void PeerConnectInfo_printf(DNDSMessage_t *msg)
{
	int ret = 0;

	size_t length;
	char *certName;

	ret = PeerConnectInfo_get_certName(msg, &certName, &length);
	printf("PeerConnectInfo> certName(%i): %s\n", ret, certName);

	char ipAddress[INET_ADDRSTRLEN];
	ret = PeerConnectInfo_get_ipAddr(msg, ipAddress);
	printf("PeerConnectInfo> ipAddr(%i): %s\n", ret, ipAddress);

	e_ConnectState state;
	ret = PeerConnectInfo_get_state(msg, &state);
	printf("PeerConnectInfo> state(%i): %i :: %s\n", ret, state, ConnectState_str(state));
}

void P2pRequest_printf(DNDSMessage_t *msg)
{
	uint8_t macAddrDst[ETHER_ADDR_LEN];
	P2pRequest_get_macAddrDst(msg, macAddrDst);
	printf("P2pRequest> macAddrDst: %x:%x:%x:%x:%x:%x\n", macAddrDst[0],macAddrDst[1],macAddrDst[2],										macAddrDst[3],macAddrDst[4],macAddrDst[5]);

	char ipAddrDst[INET_ADDRSTRLEN];
	P2pRequest_get_ipAddrDst(msg, ipAddrDst);
	printf("P2pRequest> ipAddrDst: %s\n", ipAddrDst);

	uint32_t port;
	P2pRequest_get_port(msg, &port);
	printf("P2pRequest> port: %i\n", port);

	e_P2pSide side;
	P2pRequest_get_side(msg, &side);
	printf("P2pRequest> side: %i :: %s\n", side, P2pSide_str(side));
}

void P2pResponse_printf(DNDSMessage_t *msg)
{
	uint8_t macAddrDst[ETHER_ADDR_LEN];
	P2pResponse_get_macAddrDst(msg, macAddrDst);
	printf("P2pResponse> macAddrDst: %x:%x:%x:%x:%x:%x\n", macAddrDst[0],macAddrDst[1],macAddrDst[2],
								macAddrDst[3],macAddrDst[4],macAddrDst[5]);
	e_DNDSResult result;
	P2pResponse_get_result(msg, &result);
	printf("P2pResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void AuthRequest_printf(DNDSMessage_t *msg)
{
	size_t length;
	char *certName;
	AuthRequest_get_certName(msg, &certName, &length);
	printf("AuthRequest> certName: %s\n", certName);
}

void AuthResponse_printf(DNDSMessage_t *msg)
{
	e_DNDSResult result;
	AuthResponse_get_result(msg, &result);
	printf("AuthResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void DelRequest_printf(DNDSMessage_t *msg)
{
	DNDSObject_PR objType;
	DelRequest_get_objectType(msg, &objType);
	printf("DelRequest> objType: %i\n", objType);
}

void DelResponse_printf(DNDSMessage_t *msg)
{
	e_DNDSResult result;
	DelResponse_get_result(msg, &result);
	printf("DelResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void ModifyRequest_printf(DNDSMessage_t *msg)
{
	DNDSObject_PR objType;
	DelRequest_get_objectType(msg, &objType);
	printf("DelRequest> objType: %i\n", objType);
}

void ModifyResponse_printf(DNDSMessage_t *msg)
{
	e_DNDSResult result;
	ModifyResponse_get_result(msg, &result);
	printf("ModifyResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void NetinfoRequest_printf(DNDSMessage_t *msg)
{
	char ipLocal[INET_ADDRSTRLEN];
	NetinfoRequest_get_ipLocal(msg, ipLocal);
	printf("NetinfoRequest> ipLocal: %s\n", ipLocal);

	char macAddr[ETHER_ADDR_LEN];
	NetinfoRequest_get_macAddr(msg, macAddr);
	printf("NetinfoRequest> macAddr: %x:%x:%x:%x:%x:%x\n", macAddr[0],macAddr[1],macAddr[2],
								macAddr[3],macAddr[4],macAddr[5]);
}

void NetinfoResponse_printf(DNDSMessage_t *msg)
{
	char ipAddress[INET_ADDRSTRLEN];
	NetinfoResponse_get_ipAddress(msg, ipAddress);
	printf("NetinfoResponse> ipAddress: %s\n", ipAddress);

	char netmask[INET_ADDRSTRLEN];
	NetinfoResponse_get_netmask(msg, netmask);
	printf("NetinfoResponse> netmask: %s\n", netmask);

	e_DNDSResult result;
	NetinfoResponse_get_result(msg, &result);
	printf("NetinfoResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void SearchRequest_printf(DNDSMessage_t *msg)
{
	DNDSObject_PR objType;
	SearchRequest_get_objectType(msg, &objType);
	printf("SearchRequest> objType: %i\n", objType);
}

void SearchResponse_printf(DNDSMessage_t *msg)
{
	e_DNDSResult result;
	SearchResponse_get_result(msg, &result);
	printf("SearchResponse> result: %i :: %s\n", result, DNDSResult_str(result));
}

void Acl_printf(DNDSObject_t *object)
{
	uint32_t id;
	Acl_get_id(object, &id);
	printf("Acl> id: %i\n", id);

	uint32_t contextId;
	Acl_get_contextId(object, &contextId);
	printf("Acl> contextId: %i\n", contextId);

	char *description; size_t length;
	Acl_get_description(object, &description, &length);
	printf("Acl> description: %s\n", description);
}

void AclGroup_printf(DNDSObject_t *object)
{
	uint32_t id;
	AclGroup_get_id(object, &id);
	printf("AclGroup> id: %i\n", id);

	uint32_t contextId;
	AclGroup_get_contextId(object, &contextId);
	printf("AclGroup> contextId: %i\n", contextId);

	char *name; size_t length;
	AclGroup_get_name(object, &name, &length);
	printf("AclGroup> name: %s\n", name);

	char *description;
	AclGroup_get_description(object, &description, &length);
	printf("AclGroup> description: %s\n", description);
}

void IpPool_printf(DNDSObject_t *object)
{
	uint32_t id;
	IpPool_get_id(object, &id);
	printf("IpPool> id: %i\n", id);

	char ipLocal[INET_ADDRSTRLEN];
	IpPool_get_ipLocal(object, ipLocal);
	printf("IpPool> ipLocal: %s\n", ipLocal);

	char ipBegin[INET_ADDRSTRLEN];
	IpPool_get_ipBegin(object, ipBegin);
	printf("IpPool> ipBegin: %s\n", ipBegin);

	char ipEnd[INET_ADDRSTRLEN];
	IpPool_get_ipEnd(object, ipEnd);
	printf("IpPool> ipEnd: %s\n", ipEnd);

	char netmask[INET_ADDRSTRLEN];
	IpPool_get_netmask(object, netmask);
	printf("IpPool> netmask: %s\n", netmask);
}

void Context_printf(DNDSObject_t *object)
{
	uint32_t id;
	Context_get_id(object, &id);
	printf("Context> id: %i\n", id);

	uint32_t ippoolId;
	Context_get_ippoolId(object, &ippoolId);
	printf("Context> ippoolId: %i\n", ippoolId);

	char *dnsZone; size_t length;
	Context_get_dnsZone(object, &dnsZone, &length);
	printf("Context> dnsZone: %s\n", dnsZone);

	uint32_t dnsSerial;
	Context_get_dnsSerial(object, &dnsSerial);
	printf("Context> dnsSerial: %i\n", dnsSerial);

	char *vhost;
	Context_get_vhost(object, &vhost, &length);
	printf("Context> vhost: %s\n", vhost);

	char *certificate;
	Context_get_certificate(object, &certificate, &length);
	printf("Context> certificate: %s\n", certificate);

	uint8_t *certificateKey;
	Context_get_certificateKey(object, &certificateKey, &length);
	printf("Context> certificateKey: ");
	int i; for (i = 0; i < length; i++) { printf("%x", certificateKey[i]); }; printf("\n");
}

void Host_printf(DNDSObject_t *object)
{
	uint32_t id;
	Host_get_id(object, &id);
	printf("Host> id: %i\n", id);

	uint32_t contextId;
	Host_get_contextId(object, &contextId);
	printf("Host> contextId: %i\n", contextId);

	uint32_t peerId;
	Host_get_peerId(object, &peerId);
	printf("Host> peerId: %i\n", peerId);

	char *name; size_t length;
	Host_get_name(object, &name, &length);
	printf("Host> name: %s\n", name);

	uint8_t macAddress[ETHER_ADDR_LEN];
	Host_get_macAddress(object, macAddress);
	printf("Host> macAddress: %x:%x:%x:%x:%x:%x\n", macAddress[0],macAddress[1],macAddress[2],
							macAddress[3],macAddress[4],macAddress[5]);
	char ipAddress[INET_ADDRSTRLEN];
	Host_get_ipAddress(object, ipAddress);
	printf("Host> ipAddress: %s\n", ipAddress);

	uint8_t status;
	Host_get_status(object, &status);
	printf("Host> status: %i\n", status);
}

void Node_printf(DNDSObject_t *object)
{
	uint32_t id;
	Node_get_id(object, &id);
	printf("Node> id: %i\n", id);

	char *name; size_t length;
	Node_get_name(object, &name, &length);
	printf("Node> name: %s\n", name);

	char ipAddress[INET_ADDRSTRLEN];
	Node_get_ipAddress(object, ipAddress);
	printf("Node> ipAddress: %s\n", ipAddress);

	char *certificate;
	Node_get_certificate(object, &certificate, &length);
	printf("Node> certificate: %s\n", certificate);

	uint8_t *certificateKey;
	Node_get_certificateKey(object, &certificateKey, &length);
	printf("Node> certficiateKey: ");
	int i; for (i = 0; i < length; i++) { printf("%x", certificateKey[i]); } printf("\n");

	uint8_t status;
	Node_get_status(object, &status);
	printf("Node> status: %i\n", status);
}

void Peer_printf(DNDSObject_t *object)
{
	uint32_t id;
	Peer_get_id(object, &id);
	printf("Peer> id: %i\n", id);

	uint32_t contextId;
	Peer_get_contextId(object, &contextId);
	printf("Peer> contextId: %i\n", contextId);

	char ipAddress[INET_ADDRSTRLEN];
	Peer_get_ipAddress(object, ipAddress);
	printf("Peer> ipAddress: %s\n", ipAddress);

	char *certificate; size_t length;
	Peer_get_certificate(object, &certificate, &length);
	printf("Peer> certficiate: %s\n", certificate);

	uint8_t *certificateKey;
	Peer_get_certificateKey(object, &certificateKey, &length);
	printf("Peer> certificateKey: ");
	int i; for (i = 0; i < length; i++) { printf("%x", certificateKey[i]); }; printf("\n");

	uint8_t status;
	Peer_get_status(object, &status);
	printf("Peer> status: %i\n", status);
}

void Permission_printf(DNDSObject_t *object)
{
}

void User_printf(DNDSObject_t *object)
{
	size_t length;

	uint32_t id;
	User_get_id(object, &id);
	printf("User> id: %i\n", id);

	uint32_t contextId;
	User_get_contextId(object, &contextId);
	printf("User> contextId: %i\n", contextId);

	char *name;
	User_get_name(object, &name, &length);
	printf("User> name: %s\n", name);

	char *password;
	User_get_password(object, &password, &length);
	printf("User> password: %s\n", password);

	char *firstname;
	User_get_firstname(object, &firstname, &length);
	printf("User> firstname: %s\n", firstname);

	char *lastname;
	User_get_lastname(object, &lastname, &length);
	printf("User> lastname: %s\n", lastname);

	char *email;
	User_get_email(object, &email, &length);
	printf("User> email: %s\n", email);

	uint8_t role;
	User_get_role(object, &role);
	printf("User> role: %i\n", role);
}

void DNDSObject_printf(DNDSObject_t *obj)
{
	DNDSObject_PR objType;
	DNDSObject_get_objectType(obj, &objType);

	switch (objType) {

		case DNDSObject_PR_acl:
			Acl_printf(obj);
			break;

		case DNDSObject_PR_aclgroup:
			AclGroup_printf(obj);
			break;

		case DNDSObject_PR_ippool:
			IpPool_printf(obj);
			break;

		case DNDSObject_PR_context:
			Context_printf(obj);
			break;

		case DNDSObject_PR_host:
			Host_printf(obj);
			break;

		case DNDSObject_PR_node:
			Node_printf(obj);
			break;

		case DNDSObject_PR_peer:
			Peer_printf(obj);
			break;

		case DNDSObject_PR_permission:
			break;

		case DNDSObject_PR_user:
			User_printf(obj);
			break;
	}
}


