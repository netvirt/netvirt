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

#ifndef REQUEST_H
#define REQUEST_H

#include <dnds.h>
#include "dsd.h"

void authRequest(struct session *session, DNDSMessage_t *msg);
void addRequest(struct session *session, DNDSMessage_t *msg);
void delRequest(struct session *session, DNDSMessage_t *msg);
void modifyRequest(struct session *session, DNDSMessage_t *msg);
void searchRequest(struct session *session, DNDSMessage_t *msg);
void peerConnectInfo(struct session *session, DNDSMessage_t *req_msg);

#endif

