/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2016
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

#ifndef CTRLER2_H
#define CTRLER2_H

#include <event2/buffer.h>
#include "ctrler.h"

#define SESSION_AUTH		0x1
#define SESSION_NOT_AUTH	0x2

struct session_info {
	struct bufferevent	*bev;
	uint8_t			 state;
};

int ctrler2_init(struct ctrler_cfg *);

#endif
