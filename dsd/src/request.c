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
#include "request.h"

void peerConnectInfo(ds_sess_t *sess, DNDSMessage_t *req_msg)
{
	PeerConnectInfo_printf(req_msg);
}

void authRequest(ds_sess_t *sess, DNDSMessage_t *req_msg)
{
	char *certName;
	size_t length;
	AuthRequest_get_certName(req_msg, &certName, &length);

	// XXX validate the certName
	// fetch the appropriate certificate
	// step_up the security
	printf("certName: %s\n", certName);

	// XXX mark the session as authenticated
	sess->auth = SESS_AUTH;

	// XXX answer the client
	DNDSMessage_t *msg;

	DNDSMessage_new(&msg);
	DNDSMessage_set_channel(msg, 0);
	DNDSMessage_set_pdu(msg, pdu_PR_dsm);

	DSMessage_set_seqNumber(msg, 0);
	DSMessage_set_ackNumber(msg, 1);
	DSMessage_set_operation(msg, dsop_PR_authResponse);
	AuthResponse_set_result(msg, DNDSResult_success);

	net_send_msg(sess->netc, msg);
}

void addRequest(ds_sess_t *sess, DNDSMessage_t *msg)
{

}

void delRequest(ds_sess_t *sess, DNDSMessage_t *msg)
{

}

void modifyRequest(ds_sess_t *sess, DNDSMessage_t *msg)
{

}

void searchRequest(ds_sess_t *sess, DNDSMessage_t *msg)
{

}
