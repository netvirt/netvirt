/*
 * Dynamic Network Directory Service
 * Copyright (C) 2010-2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#ifndef DND_REQUEST_H
#define DND_REQUEST_H

#include <dnds/dnds.h>
#include "session.h"

int authRequest(struct session *session, DNDSMessage_t *msg);
void p2pRequest(struct session *session_a, struct session *session_b);

#endif
