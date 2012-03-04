/*
 * request.c: Request handler API
 *
 * Copyright (C) 2010 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <dnds/dnds.h>
#include <dnds/journal.h>
#include <dnds/pki.h>

#include "request.h"
#include "context.h"

/* TODO
 * clean this prototype
 */
int authRequest(session_t *session, DNDSMessage_t *req_msg)
{
	char *certName;
	size_t length;
	size_t nbyte;
	uint8_t valid;
	uint8_t step_up;

	if (session->auth != SESS_NOT_AUTHENTICATED) {
		JOURNAL_NOTICE("dnd]> authRequest duplicate");
		return;
	}

	DNDSMessage_t *msg = NULL;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dnm);

	DNMessage_set_seqNumber(msg, 1);
	DNMessage_set_ackNumber(msg, 0);
	DNMessage_set_operation(msg, dnop_PR_authResponse);

	AuthRequest_get_certName(req_msg, &certName, &length);

	// TODO - validate certificate
	// fetch the appropriate certificate
	valid = strncmp(certName, "nib@1", length);
	if (valid == 0) {
		// FIXME - load the right context
		session->context = context_lookup(1);

		if (session->netc->security_level == NET_UNSECURE) {

			AuthResponse_set_result(msg, DNDSResult_success);
			nbyte = net_send_msg(session->netc, msg);
			session->auth = SESS_WAIT_STEP_UP;
			session->netc->on_secure(session->netc);
		}
		else {

	
			AuthResponse_set_result(msg, DNDSResult_secureStepUp);
			nbyte = net_send_msg(session->netc, msg);

			#include "certificates.h"
			passport_t *dnd_ctx_passport;
			dnd_ctx_passport = pki_passport_load_from_memory(dnd_ctx1_cert_pem,
									 dnd_ctx1_privkey_pem, 
									 dsd_ctx1_cert_pem);

			krypt_add_passport(session->netc->kconn, dnd_ctx_passport);
			session->auth = SESS_WAIT_STEP_UP;
			net_step_up(session->netc);

		}
	}
	else {

		AuthResponse_set_result(msg, DNDSResult_insufficientAccessRights);
		nbyte = net_send_msg(session->netc, msg);

		return -1;
	}

	return 0;
}

