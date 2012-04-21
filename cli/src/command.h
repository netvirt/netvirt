/*
 * command.h: Command prompt
 * Copyright 2012. Jamael Seun
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#ifndef DNDSCLI_COMMAND_H
#define DNDSCLI_COMMAND_H

#include <dnds/cli.h>

typedef struct command_list command_list_t;
struct command_list {
	command_list_t *next;
	char command[CLICMDSIZ];
};

extern int command_init(cli_socket_t *);
extern int command_list_fetch(cli_socket_t *);
extern void command_set_completion();

#endif /* DNDSCLI_COMMAND_H */
