/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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

#include "agent.h"
#include "p2p.h"
#include "session.h"

struct agent_cfg *agent_cfg;
struct session *master_session;
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

	net_get_local_ip(ip_local, INET_ADDRSTRLEN);
	hwaddr = tapcfg_iface_get_hwaddr(session->tapcfg, &hwaddrlen);

	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 0);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_netinfoRequest);

	NetinfoRequest_set_ipLocal(msg, ip_local);
	NetinfoRequest_set_macAddr(msg, (uint8_t*)hwaddr);

	net_send_msg(session->netc, msg);
	DNDSMessage_del(msg);

}

void transmit_prov_request(netc_t *netc)
{
	ssize_t nbyte;
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_provRequest);

	ProvRequest_set_provCode(msg, agent_cfg->prov_code, strlen(agent_cfg->prov_code));

	nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
	if (nbyte == -1) {
		jlog(L_NOTICE, "malformed message", nbyte);
		return;
	}
}

void transmit_register(netc_t *netc)
{
	X509_NAME *subj_ptr;
	char subj[256];
        ssize_t nbyte;
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

	jlog(L_NOTICE, "CN=%s", subj);
        AuthRequest_set_certName(msg, subj, strlen(subj));

        nbyte = net_send_msg(netc, msg);
	DNDSMessage_del(msg);
        if (nbyte == -1) {
                jlog(L_NOTICE, "malformed message: %d", nbyte);
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

	while (agent_cfg->agent_running) {
#if defined(_WIN32)
		Sleep(5);
#else
		sleep(5);
#endif

		retry_netc = net_client(agent_cfg->server_address, agent_cfg->server_port,
			NET_PROTO_UDT, NET_SECURE_ADH, session->passport,
			on_disconnect, on_input, on_secure);

		if (retry_netc) {
			session->state = SESSION_STATE_NOT_AUTHED;
			session->netc = retry_netc;
			retry_netc->ext_ptr = session;
			return NULL;
		}
	}

	return NULL;
}

static void on_disconnect(netc_t *netc)
{
	jlog(L_NOTICE, "disconnected...");

	pthread_t thread_reconnect;
	struct session *session;

	session = netc->ext_ptr;
	netc->ext_ptr = NULL;
	if (session == NULL) {
		jlog(L_DEBUG, "session is NULL");
		return;
	}

	if (session->state == SESSION_STATE_DOWN) {
		jlog(L_DEBUG, "session->state == SESSION_STATE_DOWN");
		return;
	}

	session->state = SESSION_STATE_DOWN;

	if (agent_cfg->ev.on_disconnect)
		agent_cfg->ev.on_disconnect();

	pthread_create(&thread_reconnect, NULL, try_to_reconnect, (void *)session);
	pthread_detach(thread_reconnect);
}

static void on_secure(netc_t *netc)
{
	struct session *session;
	session = netc->ext_ptr;

	jlog(L_NOTICE, "connection secured");

	if (session->state == SESSION_STATE_NOT_AUTHED) {
		if (session->passport == NULL && agent_cfg->prov_code != NULL) {
			jlog(L_NOTICE, "Provisioning mode...");
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

static void op_netinfo_response(struct session *session)
{
	FILE *fp = NULL;
	int fret = 0;

	fp = fopen(agent_cfg->ip_conf, "r");
	if (fp == NULL) {
		jlog(L_ERROR, "%s doesn't exist, reprovision your agent", agent_cfg->ip_conf);
		return;
	}
	fret = fscanf(fp, "%s", ipAddress);
	if (fret == EOF) {
		jlog(L_ERROR, "can't fetch IP address from file: %s\n", agent_cfg->ip_conf);
	}
	fclose(fp);

	tapcfg_iface_set_status(session->tapcfg, TAPCFG_STATUS_IPV4_UP);
	tapcfg_iface_set_ipv4(session->tapcfg, ipAddress, 24);
	jlog(L_NOTICE, "ip address: %s", ipAddress);
	session->state = SESSION_STATE_AUTHED;
}

static void op_auth_response(struct session *session, DNDSMessage_t *msg)
{
	e_DNDSResult result;
	AuthResponse_get_result(msg, &result);
	FILE *fp = NULL;
	int fret = 0;

	switch (result) {
	case DNDSResult_success:
		krypt_print_cipher(session->netc->kconn);
		jlog(L_NOTICE, "session secured and authenticated");

		fp = fopen(agent_cfg->ip_conf, "r");
		if (fp) {
			fret = fscanf(fp, "%s", ipAddress);
			if (fret == EOF) {
				jlog(L_ERROR, "can't fetch IP address from file: %s\n", agent_cfg->ip_conf);
			}
			fclose(fp);
		}
		if (agent_cfg->ev.on_connect)
			agent_cfg->ev.on_connect(ipAddress);

		transmit_netinfo_request(session);
		break;

	case DNDSResult_secureStepUp:
		jlog(L_NOTICE, "server authentication require step up");
		break;

	case DNDSResult_insufficientAccessRights:
		jlog(L_ERROR, "authentication failed, invalid certificate");
		break;

	default:
		jlog(L_NOTICE, "unknown AuthResponse result (%i)", result);
	}
}

static void create_file_with_owner_right(const char *filename)
{
	int fd = 0;
	fd = open(filename, O_CREAT, S_IRUSR|S_IWUSR);
	if (fd != -1)
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
		jlog(L_ERROR, "Invalid provisioning key");
		return;
	}

	create_file_with_owner_right(agent_cfg->certificate);
	fp = fopen(agent_cfg->certificate, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "can't write certifcate in file '%s'", agent_cfg->certificate);
		return;
	}
	fwrite(certificate, 1, strlen(certificate), fp);
	fclose(fp);

	ProvResponse_get_certificateKey(msg, &certificatekey, &length);
	create_file_with_owner_right(agent_cfg->privatekey);
	fp = fopen(agent_cfg->privatekey, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "can't write private key in file '%s'", agent_cfg->privatekey);
		return;
	}
	fwrite(certificatekey, 1, strlen((char*)certificatekey), fp);
	fclose(fp);

	ProvResponse_get_trustedCert(msg, &trusted_authority, &length);
	create_file_with_owner_right(agent_cfg->trusted_cert);
	fp = fopen(agent_cfg->trusted_cert, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "can't write trusted certificate in file '%s'", agent_cfg->trusted_cert);
		return;
	}
	fwrite(trusted_authority, 1, strlen((char *)trusted_authority), fp);
	fclose(fp);

	ProvResponse_get_ipAddress(msg, ipAddress);

	fp = fopen(agent_cfg->ip_conf, "w");
	if (fp == NULL) {
		jlog(L_ERROR, "can't write IP address in file '%s'", agent_cfg->ip_conf);
		return;
	}
	fprintf(fp, "%s", ipAddress);
	fclose(fp);

	session->passport = pki_passport_load_from_file(agent_cfg->certificate,
					 agent_cfg->privatekey,
					 agent_cfg->trusted_cert);

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
		op_netinfo_response(session);
		break;

	case dnop_PR_p2pRequest:
		op_p2p_request(session, msg);
		break;

	/* `terminateRequest` is a special case since it has no
	 * response message associated with it, simply disconnect.
	 */
	case dnop_PR_NOTHING:
	default:
		jlog(L_NOTICE, "not a valid DNM operation");
	case dnop_PR_terminateRequest:
		terminate(session);
		break;
	}
}

static void *agent_loop(void *session)
{
	while (agent_cfg->agent_running) {
		udtbus_poke_queue();
		if (tapcfg_wait_readable(((struct session *)session)->tapcfg, 0))
			tunnel_in((struct session *)session);
	}

	return NULL;
}

void agent_init_async(struct agent_cfg *cfg)
{
	pthread_t agent_init_async;
	pthread_create(&agent_init_async, NULL, agent_init, (void*)cfg);
}

static pthread_t thread_reconnect;
static pthread_t thread_loop;
static struct session *session;

void agent_fini()
{
	pthread_join(thread_reconnect, NULL);
	pthread_join(thread_loop, NULL);

	net_disconnect(session->netc);
	tapcfg_destroy(session->tapcfg);
	pki_passport_destroy(session->passport);

	p2p_fini();
	netbus_fini();

	free(session);
}

void *agent_init(void *cfg)
{

	agent_cfg = (struct agent_cfg *)cfg;

	session = calloc(1, sizeof(struct session));

	p2p_init();

	if (netbus_init()) {
		jlog(L_ERROR, "netbus_init failed");
		return NULL;
	}

	if (krypt_init()) {
		jlog(L_ERROR, "krypt_init failed");
		return NULL;
	}

	if (agent_cfg->prov_code == NULL)
		session->passport = pki_passport_load_from_file(
			agent_cfg->certificate, agent_cfg->privatekey, agent_cfg->trusted_cert);

	if (session->passport == NULL && agent_cfg->prov_code == NULL) {
		jlog(L_ERROR, "Must provide a provisioning code: ./nvagent -p ...");
		free(session);
		return NULL;
	}

	session->tapcfg = NULL;
	session->state = SESSION_STATE_NOT_AUTHED;

	session->tapcfg = tapcfg_init();
	if (session->tapcfg == NULL) {
		jlog(L_ERROR, "tapcfg_init failed");
		free(session);
		return NULL;
	}

	if (tapcfg_start(session->tapcfg, "netvirt0", 1) < 0) {
		jlog(L_ERROR, "tapcfg_start failed");
		free(session);
		return NULL;
	}

	session->devname = tapcfg_get_ifname(session->tapcfg);
	jlog(L_DEBUG, "devname: %s", session->devname);

	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	agent_cfg->agent_running = 1;
	pthread_create(&thread_reconnect, &attr, try_to_reconnect, (void *)session);
	pthread_create(&thread_loop, &attr, agent_loop, session);

	return NULL;
}
