/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details
 */

#ifndef REQUEST_H
#define REQUEST_H

#include <dnds.h>
#include "ctrler.h"

void authRequest(struct session *session, DNDSMessage_t *msg);
void addRequest(DNDSMessage_t *msg);
void delRequest(struct session *session, DNDSMessage_t *msg);
void modifyRequest(struct session *session, DNDSMessage_t *msg);
void searchRequest(struct session *session, DNDSMessage_t *msg);
void peerConnectInfo(struct session *session, DNDSMessage_t *req_msg);
void nodeConnectInfo(struct session *session, DNDSMessage_t *req_msg);

#endif

