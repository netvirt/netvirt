/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
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

#include <jansson.h>
#include <dnds.h>
#include "ctrler.h"
#include "ctrler2.h"

void authRequest(struct session *session, DNDSMessage_t *msg);
void addRequest(DNDSMessage_t *msg);
void delRequest(struct session *session, DNDSMessage_t *msg);
void modifyRequest(struct session *session, DNDSMessage_t *msg);
void searchRequest(struct session *session, DNDSMessage_t *msg);
void peerConnectInfo(struct session *session, DNDSMessage_t *req_msg);
void nodeConnectInfo(struct session *session, DNDSMessage_t *req_msg);


void addNode(struct session_info *, json_t *);
void addAccount(struct session_info *, json_t *);
void getAccountApiKey(struct session_info *, json_t *);
void addNetwork(struct session_info *, json_t *);
void listNetwork(struct session_info *, json_t *);
void listNode(struct session_info *, json_t *);
void activateAccount(struct session_info *, json_t *);
void delNetwork(struct session_info *, json_t *);
void delNode(struct session_info *sinfo, json_t *jmsg);

#endif

