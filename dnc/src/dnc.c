/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>


#include <dnds.h>
#include <logger.h>
#include <mbuf.h>
#include <netbus.h>

#include "dnc.h"
#include "p2p.h"
#include "session.h"

struct dnc_cfg *dnc_cfg;
struct session *master_session;
static int g_shutdown = 0;
char ipAddress[INET_ADDRSTRLEN];

void on_input(netc_t *netc);
static void on_secure(netc_t *netc);
static void dispatch_op(struct session *session, DNDSMessage_t *msg);
static void on_disconnect(netc_t *netc);

static void tunnel_in(struct session* session)
{
	DNDSMessage_t *msg = NULL;
	size_t frame_size = 0;
	uint8_t framebuf[2000];
	struct session *p2p_session;

	frame_size = tapcfg_read(session->tapcfg, framebuf, 2000);
	p2p_session = p2p_find_session(framebuf);
	if (p2p_session) {
		//printf("p2p_session: %p netc: %p\n", p2p_session, p2p_session->netc);
		session = p2p_session;
	}

	if (session->state != SESSION_STATE_AUTHED)
		return;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_ethernet);
	DNDSMessage_set_ethernet(msg, (uint8_t*)framebuf, frame_size);

	net_send_msg(session->netc, msg);
	DNDSMessage_set_ethernet(msg, NULL, 0);
	DNDSMessage_del(msg);
}

static void tunnel_out(struct session *session, DNDSMessage_t *msg)
{
	uint8_t *framebuf;
	size_t framebufsz;

	DNDSMessage_get_ethernet(msg, &framebuf, &framebufsz);
	tapcfg_write(session->tapcfg, framebuf, framebufsz);
}

void terminate(struct session *session)
{
	session->state = SESSION_STATE_DOWN;
	net_disconnect(session->netc);
	session->netc = NULL;
}

void transmit_netinfo_request(struct session *session)
{
	const char *hwaddr;
	int hwaddrlen;
	char ip_local[16];

//	inet_get_local_ip(ip_local, INET_ADDRSTRLEN);
	hwaddr = tapcfg_iface_get_hwaddr(session->tapcfg, &hwaddrlen);

	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoRequest);

	NetinfoRequest_set_ipLocal(msg, ip_local); // Is it still usefull ?
	NetinfoRequest_set_macAddr(msg, (uint8_t*)hwaddr);

	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);

}

void transmit_prov_request(netc_t *netc)
{
	size_t nbyte;
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_provRequest);

	ProvRequest_set_provCode(msg, dnc_cfg->prov_code, strlen(dnc_cfg->prov_code));

	nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
	if (nbyte == -1) {
		jlog(L_NOTICE, "dnc]> malformed message", nbyte);
		return;
	}
}

void transmit_register(netc_t *netc)
{
	X509_NAME *subj_ptr;
	char subj[256];
        size_t nbyte;
	struct session *session = (struct session *)netc->ext_ptr;

        DNDSMessage_t *msg;

        DNDSMessage_new(&msg);
        DNDSMessage_set_channel(msg, 0);
        DNDSMessage_set_pdu(msg, pdu_PR_dnm);

        DNMessage_set_seqNumber(msg, 1);
        DNMessage_set_ackNumber(msg, 0);
        DNMessage_set_operation(msg, dnop_PR_authRequest);

	subj_ptr = X509_get_subject_name(session->passport->certificate);
	X509_NAME_get_text_by_NID(subj_ptr, NID_commonName, subj, 256);

	jlog(L_NOTICE, "dnc]> CN=%s", subj);
        AuthRequest_set_certName(msg, subj, strlen(subj));

        nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
        if (nbyte == -1) {
                jlog(L_NOTICE, "dnc]> malformed message: %d", nbyte);
                return;
        }
	session->state = SESSION_STATE_WAIT_ANSWER;

	/* Prepare to the re-handshake, set up certificates */
	krypt_set_rsa(session->netc->kconn);

        return;
}

void *try_to_reconnect(void *ptr)
{
	struct session *session = NULL;
	netc_t *retry_netc = NULL;

	session = (struct session *)ptr;

	do {
#if defined(_WIN32)
		Sleep(5);
#else
		sleep(5);
#endif

		retry_netc = net_client(dnc_cfg->server_address, dnc_cfg->server_port,
			NET_PROTO_UDT, NET_SECURE_ADH, session->passport,
			on_disconnect, on_input, on_secure);

		if (retry_netc) {
			session->state = SESSION_STATE_NOT_AUTHED;
			session->netc = retry_netc;
			retry_netc->ext_ptr = session;
			return NULL;
		}
	} while (!g_shutdown);

	return NULL;
}

static void on_disconnect(netc_t *netc)
{
	jlog(L_NOTICE, "dnc]> disconnected...");

	pthread_t thread_reconnect;
	struct session *session;

	session = netc->ext_ptr;
	if (session == NULL || session->state == SESSION_STATE_DOWN)
		return;

	session->state = SESSION_STATE_DOWN;

	if (dnc_cfg->ev.on_disconnect)
		dnc_cfg->ev.on_disconnect();

	jlog(L_NOTICE, "dnc]> connection retry...");
	pthread_create(&thread_reconnect, NULL, try_to_reconnect, (void *)session);
	pthread_detach(thread_reconnect);
}

static void on_secure(netc_t *netc)
{
	struct session *session;
	session = netc->ext_ptr;

	jlog(L_NOTICE, "dnc]> connection secured");

	if (session->state == SESSION_STATE_NOT_AUTHED) {
		if (session->passport == NULL || dnc_cfg->prov_code != NULL) {
			jlog(L_NOTICE, "dnc]> Provisioning mode...");
			transmit_prov_request(netc);
		}
		else {
			transmit_register(netc);
		}

	}
}

void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	struct session *session;
	mbuf_t **mbuf_itr;
	pdu_PR pdu;

	mbuf_itr = &netc->queue_msg;
	session = netc->ext_ptr;

	while (*mbuf_itr != NULL) {
		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;
		DNDSMessage_get_pdu(msg, &pdu);

		switch (pdu) {
		case pdu_PR_dnm:
			dispatch_op(session, msg);
			break;

		case pdu_PR_ethernet:
			tunnel_out(session, msg);
			break;

		default: /* Invalid PDU */
			terminate(session);
			return;
		}
		mbuf_del(mbuf_itr, *mbuf_itr);
	}
}

static void op_netinfo_response(struct session *session, DNDSMessage_t *msg)
{
	FILE *fp = NULL;

	fp = fopen(DNC_IP_FILE, "r");
	if (fp == NULL) {
		jlog(L_ERROR, "%s doesn't exist, reprovision your client", DNC_IP_FILE);
		return;
	}
	fscanf(fp, "%s", ipAddress);
	fclose(fp);

	tapcfg_iface_set_ipv4(session->tapcfg, ipAddress, 24);
	tapcfg_iface_set_status(session->tapcfg, TAPCFG_STATUS_IPV4_UP);
	session->state = SESSION_STATE_AUTHED;
}

static void op_auth_response(struct session *session, DNDSMessage_t *msg)
{
	e_DNDSResult result;
	AuthResponse_get_result(msg, &result);
	FILE *fp = NULL;

	switch (result) {
	case DNDSResult_success:
		jlog(L_NOTICE, "dnc]> session secured and authenticated");

		fp = fopen(DNC_IP_FILE, "r");
		if (fp) {
			fscanf(fp, "%s", ipAddress);
			fclose(fp);
		}
		if (dnc_cfg->ev.on_connect)
			dnc_cfg->ev.on_connect(ipAddress);

		transmit_netinfo_request(session);
		break;

	case DNDSResult_secureStepUp:
		jlog(L_NOTICE, "dnc]> server authentication require step up");

		break;

	default:
		jlog(L_NOTICE, "dnc]> unknown AuthResponse result (%i)", result);
	}
}

static void create_file_with_owner_right(const char *filename)
{
	int fd = 0;
	fd = open(filename, O_CREAT, S_IRUSR|S_IWUSR);
	close(fd);
}

static void op_prov_response(struct session *session, DNDSMessage_t *msg)
{
	size_t length;
	char *certificate = NULL;
	unsigned char *certificatekey = NULL;
	unsigned char *trusted_authority = NULL;
	FILE *fp = NULL;

	ProvResponse_get_certificate(msg, &certificate, &length);
	if (certificate == NULL) {
		jlog(L_ERROR, "dnc]> Invalid provisioning key");
		return;
	}

	create_file_with_owner_right(dnc_cfg->certificate);
	fp = fopen(dnc_cfg->certificate, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "dnc]> can't write certifcate in file '%s'", dnc_cfg->certificate);
		return;
	}
	fwrite(certificate, 1, strlen(certificate), fp);
	fclose(fp);

	ProvResponse_get_certificateKey(msg, &certificatekey, &length);
	create_file_with_owner_right(dnc_cfg->privatekey);
	fp = fopen(dnc_cfg->privatekey, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "dnc]> can't write private key in file '%s'", dnc_cfg->privatekey);
		return;
	}
	fwrite(certificatekey, 1, strlen((char*)certificatekey), fp);
	fclose(fp);

	ProvResponse_get_trustedCert(msg, &trusted_authority, &length);
	create_file_with_owner_right(dnc_cfg->trusted_cert);
	fp = fopen(dnc_cfg->trusted_cert, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "dnc]> can't write trusted certificate in file '%s'", dnc_cfg->trusted_cert);
		return;
	}
	fwrite(trusted_authority, 1, strlen((char *)trusted_authority), fp);
	fclose(fp);

	ProvResponse_get_ipAddress(msg, ipAddress);
	jlog(L_NOTICE, "dnc]> ip address: %s", ipAddress);

	fp = fopen(DNC_IP_FILE, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "dnc]> can't write IP address in file '%s'", DNC_IP_FILE);
		return;
	}
	fprintf(fp, "%s", ipAddress);
	fclose(fp);

	session->passport = pki_passport_load_from_file(dnc_cfg->certificate,
					 dnc_cfg->privatekey,
					 dnc_cfg->trusted_cert);

	krypt_add_passport(session->netc->kconn, session->passport);
	transmit_register(session->netc);
}

static void dispatch_op(struct session *session, DNDSMessage_t *msg)
{
	dnop_PR operation;
	DNMessage_get_operation(msg, &operation);

	switch (operation) {
	case dnop_PR_provResponse:
		op_prov_response(session, msg);
		break;

	case dnop_PR_authResponse:
		op_auth_response(session, msg);
		break;

	case dnop_PR_netinfoResponse:
		op_netinfo_response(session, msg);
		break;

	case dnop_PR_p2pRequest:
		op_p2p_request(session, msg);
		break;

	/* `terminateRequest` is a special case since it has no
	 * response message associated with it, simply disconnect the client.
	 */
	case dnop_PR_NOTHING:
	default:
		jlog(L_NOTICE, "dnc]> not a valid DNM operation");
	case dnop_PR_terminateRequest:
		terminate(session);
		break;
	}
}

static void *dnc_loop(void *session)
{
	while (!g_shutdown) {
		udtbus_poke_queue();
		if (tapcfg_wait_readable(((struct session *)session)->tapcfg, 0))
			tunnel_in((struct session *)session);
	}
	return NULL;
}

void dnc_init_async(struct dnc_cfg *cfg)
{
	pthread_t dnc_init_async;
	pthread_create(&dnc_init_async, NULL, dnc_init, (void*)cfg);
}

void *dnc_init(void *cfg)
{
	struct session *session;

	dnc_cfg = (struct dnc_cfg *)cfg;
	session = calloc(1, sizeof(struct session));

	p2p_init();

	if (netbus_init()) {
		jlog(L_ERROR, "dnc]> netbus_init failed :: %s:%i", __FILE__, __LINE__);
		return NULL;
	}

	if (krypt_init()) {
		jlog(L_ERROR, "dnc]> krypt_init failed :: %s:%i", __FILE__, __LINE__);
		return NULL;
	}

	if (dnc_cfg->prov_code == NULL)
		session->passport = pki_passport_load_from_file(
			dnc_cfg->certificate, dnc_cfg->privatekey, dnc_cfg->trusted_cert);

	if (session->passport == NULL && dnc_cfg->prov_code == NULL) {
		jlog(L_ERROR, "dnc]> Must provide a provisioning code: ./dnc -p ...");
		free(session);
		return NULL;
	}

	session->tapcfg = NULL;
	session->state = SESSION_STATE_NOT_AUTHED;

	session->tapcfg = tapcfg_init();
	if (session->tapcfg == NULL) {
		jlog(L_ERROR, "dnc]> tapcfg_init failed");
		return NULL;
	}

	if (tapcfg_start(session->tapcfg, "dynvpn0", 1) < 0) {
		jlog(L_ERROR, "dnc]> tapcfg_start failed");
		return NULL;
	}

	session->devname = tapcfg_get_ifname(session->tapcfg);
	jlog(L_DEBUG, "dnc]> devname: %s", session->devname);

	pthread_t thread_reconnect;
	pthread_create(&thread_reconnect, NULL, try_to_reconnect, (void *)session);
	pthread_detach(thread_reconnect);

	pthread_t thread_loop;
	pthread_create(&thread_loop, NULL, dnc_loop, session);

	return NULL;
}
