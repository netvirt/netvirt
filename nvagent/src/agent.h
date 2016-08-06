/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) mind4networks inc. 2009-2016
 * Nicolas J. Bouliane <nib@m4nt.com>
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

#ifndef NVAGENT_H
#define nvAGENT_H

#ifdef __cplusplus
extern "C" {
#endif

void	agent_fini(void);
int	agent_init(void);

#ifdef __cplusplus
}
#endif

#endif
