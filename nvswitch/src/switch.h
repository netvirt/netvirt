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

#ifndef SWITCH_H
#define SWITCH_H

#include "context.h"

struct switch_cfg {

	const char *log_file;

	const char *listen_ip;
	const char *listen_port;

	const char *ctrler_ip;
	const char *ctrler_port;

	const char *certificate;
	const char *privatekey;
	const char *trusted_cert;

	int ctrl_initialized;
	int ctrl_running;
	int switch_running;
};

int switch_init(struct switch_cfg *switch_cfg);
void switch_fini();

#endif
