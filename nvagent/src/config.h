/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "agent.h"

#ifdef __cplusplus
extern "C" {
#endif

char *agent_config_get_fullname(const char *profile, const char *file);
int agent_config_init(struct agent_cfg *agent_cfg);
void agent_config_destroy(struct agent_cfg *agent_cfg);

#ifdef __cplusplus
}
#endif

#endif

