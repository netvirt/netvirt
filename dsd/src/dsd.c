/* Directory Service Daemon
 *
 * Copyright (C) 2010, 2011 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds/dnds.h>
#include <dnds/event.h>
#include <dnds/journal.h>
#include <dnds/net.h>
#include <dnds/pki.h>

#include "dsd.h"
#include "request.h"

static void session_free(ds_sess_t *sess)
{
	free(sess);
}

static ds_sess_t *session_new()
{
	ds_sess_t *sess = calloc(1, sizeof(ds_sess_t));
	sess->auth = SESS_NOT_AUTH;
}

static void terminate(ds_sess_t *sess)
{
	net_disconnect(sess->netc);
	session_free(sess);
}

static int validate_msg(DNDSMessage_t *msg)
{
	pdu_PR pdu;
	DNDSMessage_get_pdu(msg, &pdu);

	if (pdu != pdu_PR_dsm) {
		JOURNAL_NOTICE("dsd]> not a valid DSM data unit");
		return -1;
	}

	return 0;
}

static void dispatch_operation(ds_sess_t *sess, DNDSMessage_t *msg)
{
	dsop_PR operation;
	DSMessage_get_operation(msg, &operation);

	switch (operation) {

		case dsop_PR_authRequest:
			authRequest(sess, msg);
			break;

		case dsop_PR_addRequest:
			addRequest(sess, msg);
			break;

		case dsop_PR_delRequest:
			delRequest(sess, msg);
			break;

		case dsop_PR_modifyRequest:
			modifyRequest(sess, msg);
			break;

		case dsop_PR_searchRequest:
			searchRequest(sess, msg);
			break;

		/* terminateRequest is a special case since
		 * it has no Response message associated with it.
		 * simply disconnect the client;
		 */
		case dsop_PR_NOTHING:
		default:
			JOURNAL_NOTICE("dsd]> not a valid DSM operation");
		case dsop_PR_terminateRequest:
			terminate(sess);
			break;
	}
}

static void on_secure(netc_t *netc)
{
	printf("on secure!\n");
}

static void on_input(netc_t *netc)
{
	DNDSMessage_t *msg;
	ds_sess_t *sess;
	mbuf_t **mbuf_itr;

	mbuf_itr = &netc->queue_msg;
	sess = (ds_sess_t *)netc->ext_ptr;

	while (*mbuf_itr != NULL) {

		msg = (DNDSMessage_t *)(*mbuf_itr)->ext_buf;
		DNDSMessage_printf(msg);

		if (validate_msg(msg) == 0)
			dispatch_operation(sess, msg);
		else {
			terminate(sess);
			return;
		}

		mbuf_del(mbuf_itr, *mbuf_itr);
	}

	return;
}

static void on_disconnect(netc_t *netc)
{
	ds_sess_t *sess;
	sess = (ds_sess_t *)netc->ext_ptr;

	session_free(sess);
}

static void timeout_session(ds_sess_t *sess)
{
	printf("time out sess\n");
// FIXME	chronos_remove(sess->timeout_id);
	terminate(sess);
}

static void on_connect(netc_t *netc)
{
	ds_sess_t *sess;

	sess = session_new();
	if (sess == NULL) {
		net_disconnect(netc);
		return;
	}

	sess->netc = netc;
	netc->ext_ptr = sess;

// FIXME	sess->timeout_id = chronos_add(5000, timeout_session, sess);
}


void dsd_fini(void *ext_ptr)
{
	// XXX free all sessions
}

int dsd_init(char *listen_addr, char *port, char *certificate, char *privatekey, char *trusted_authority)
{
	int ret;

	event_register(EVENT_EXIT, "dsd_fini", dsd_fini, PRIO_AGNOSTIC);

	passport_t *dsd_passport;
	dsd_passport = pki_passport_load_from_file(certificate, privatekey, trusted_authority);

	ret = net_server(listen_addr, port, NET_PROTO_UDT, NET_SECURE_RSA, dsd_passport,
			on_connect, on_disconnect, on_input, on_secure);

	if (ret < 0) {
		JOURNAL_NOTICE("dsd]> net_server failed :: %s:%i\n", __FILE__, __LINE__);
		return -1;
	}

	return 0;
}
