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

int authRequest(struct session *session, DNDSMessage_t *msg);
void p2pRequest(struct session *session_a, struct session *session_b);

#endif
