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

#ifndef SWITCH_H
#define SWITCH_H

#include <jansson.h>

struct switch_config {

	const char	*log_file;

	const char	*switch_ip;
	const char	*switch_port;

	const char	*control_ip;
	const char	*control_port;
	const char	*certificate;
	const char	*privatekey;
	const char	*trustedcert;
};

void	 switch_init(json_t *);
void	 switch_fini(void);

#endif
