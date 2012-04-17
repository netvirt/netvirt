/*
 * cli.c: Command line interface API
 * Copyright 2012. The OpenDNDS team. <team@opendnds.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "cli.h"
#include "journal.h"
#include "usocket.h"

static char const module_name[] = "cli";

static int handle_help(cli_entry_t *, int, cli_args_t *);
static int handle_list(cli_entry_t *, int, cli_args_t *);
static int handle_quit(cli_entry_t *, int, cli_args_t *);

static cli_entry_t cli_commands[] = {
	CLI_ENTRY(handle_help, "Show commands information"),
	CLI_ENTRY(handle_list, "List available commands"),
	CLI_ENTRY(handle_quit, "Disconnect console"),
};

static void close_socket(usocket_t *);
static void server_read_socket(usocket_t *);
static usocket_handler_t cli_server_handler = {
	.recv = server_read_socket,
	.close = close_socket,
};

static void console_read_socket(usocket_t *);
static usocket_handler_t cli_console_handler = {
	.recv = console_read_socket,
	.close = close_socket,
};

static int args_process(char *s, cli_args_t *a)
{
	int blank = 1, quote = 0;
	int pos = 0, count = 0;

	a->perror = 0;

	/* skip leading blank */
	while(isblank(*s)) {
		s++;
		pos++;
	}

	while (*s) {
		pos++;
		if (count >= CLIARGVSIZ) {
			/* parsing error, max arguments reached */
			a->perror = CLIARGPEMAR;
			a->pe_near = pos;
			return -1;
		}

		if (isblank(*s) && !quote) {
			/* blank is found; not quoted, not escaped */
			*s = '\0';
			blank = 1;
		} else if (*s == '"' && quote) {
			/* end quote */
			*s = '\0';
			blank = quote = 0;
		} else if (*s == '"' && blank) {
			/* start quote */
			quote = 1;
		} else if (*s == '"' && !blank) {
			/* parsing error, no blank before quote */
			a->perror = CLIARGPEBBQ;
			a->pe_near = pos;
			return -1;
		} else if (blank) {
			count++;
			a->argv[count] = s;
			blank = 0;
		}
		s++;
	}

	if (quote) {
		/* parsing error, no end quote */
		a->perror = CLIARGPENEQ;
		a->pe_near = pos;
		return -1;
	}

	return count;
}

static void close_socket(usocket_t *su)
{
	assert(su != NULL);
	usocket_close(su);
}

static void server_read_socket(usocket_t *su)
{
	cli_server_t *server;
	cli_summary_t *cs;
	cli_args_t args = { 0 };

	assert(su);
	server = su->udata;
	cs = cli_read_summary(su->buf);
	if (cs) {
		args.fd = su->fd;
		args.out = su->buf;
		args.command_list = server->command_list;
		cs->retval = cli_exec(cs, &args, server->command_list);
		cli_send_summary(su->buf, cs);
		free(cs);
	}
}

static void console_read_socket(usocket_t *su)
{
	JOURNAL_ERR("cli]> caller must register socket handlers :: %s:%i",
		__FILE__, __LINE__);
}

static int handle_help(cli_entry_t *e, int cmd, cli_args_t *a)
{
	cli_entry_t *entry;
	cli_list_t *p;
	int i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "help";
		e->usage = "Usage: help [command]\n"
			   "       Show available commands and description.\n"
			   "\n"
			   "If a command name is specified, it prints the "
			   "usage notice of that command.";
		return CLI_RETURN_SUCCESS;
	}

	if (a->argc == 1) {
		entry = cli_find_entry(a->argv[1], a->command_list);
		if (entry) {
			cli_print_usage(a->out, entry);
			return CLI_RETURN_SUCCESS;
		}
		
		cli_print(a->out, "help: no such command `%s'\n", a->argv[1]);
		return CLI_RETURN_FAILURE;
	} else if (a->argc > 1)
		return CLI_RETURN_SHOWUSAGE;

	for (p = a->command_list; p != NULL; p = p->next) {
		cli_print(a->out, "from `%s':\n", p->module_name);
		for (i = 0, entry = p->entry; i < p->entry_count; i++)
			cli_print(a->out, "%-*s\t%s\n",
			    CLICMDSIZ, entry[i].command, entry[i].desc);
	}
	return CLI_RETURN_SUCCESS;
}

static int handle_list(cli_entry_t *e, int cmd, cli_args_t *a)
{
	cli_entry_t *entry;
	cli_list_t *p;
	int i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "list";
		e->usage = "Usage: list\n"
			   "       List available commands one per line";
		return CLI_RETURN_SUCCESS;
	}

	if (a->argc)
		return CLI_RETURN_SHOWUSAGE;

	for (p = a->command_list; p != NULL; p = p->next)
		for (i = 0, entry = p->entry; i < p->entry_count; i++)
			cli_print(a->out, "%s\n", entry[i].command);
	return CLI_RETURN_SUCCESS;
}

static int handle_quit(cli_entry_t *e, int cmd, cli_args_t *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "quit";
		e->usage = "Usage: quit\n"
			   "       Shutdown communication with console";
		return CLI_RETURN_SUCCESS;
	}

	if (a->argc)
		return CLI_RETURN_SHOWUSAGE;

	shutdown(a->fd, SHUT_RD);
	return CLI_RETURN_SHUTDOWN;
}

int cli_free_entry_all(cli_list_t *head)
{
	cli_list_t *p;
	for (p = head; p != NULL; p = p->next)
		free(p);
	return 0;
}

cli_entry_t *cli_find_entry(char *command, cli_list_t *head) {
	cli_entry_t *entry;
	cli_list_t *p;
	int i;

	for (p = head; p != NULL; p = p->next)
		for (i = 0, entry = p->entry; i < p->entry_count; i++)
			if (strcmp(command, entry[i].command) == 0)
				return &(entry[i]);
	return NULL;
}

int cli_print_usage(FILE *out, cli_entry_t *e)
{
	if (strlen(e->usage)) {
		cli_print(out, "%s\n", e->usage);
		return 0;
	}
	return -1;
}

int cli_exec(cli_summary_t *cs, cli_args_t *a, cli_list_t *head)
{
	cli_entry_t *entry = NULL;
	char args[CLIARGSSIZ] = { 0 };
	int ret = CLI_RETURN_INVALID;

	cli_buffer_start(a->out);
	entry = cli_find_entry(cs->command, head);
	if (entry && entry->handler) {
		a->argv[0] = cs->command;
		strncpy(args, cs->args, CLIARGSSIZ-1);
		a->argc = args_process(args, a);
		if (a->perror) {
			cli_print(a->out, "Parsing error near `%s': %s\n",
			    &(cs->args[a->pe_near]),
			    cli_args_perror(a->perror));
			ret = CLI_RETURN_FAILURE;
		} else
			ret = entry->handler(entry, CLI_EXEC, a);

		if (ret == CLI_RETURN_SHOWUSAGE)
			cli_print_usage(a->out, entry);
	}
	cli_buffer_end(a->out);
	return ret;
}

int cli_register_entry(cli_list_t **head, char const *module_name,
                       cli_entry_t *entry, size_t count)
{
	cli_list_t *p;
	int i;

	for (i = 0; i < count; i++)
		if (entry[i].handler)
			entry[i].handler(&(entry[i]), CLI_INIT, NULL);

	p = calloc(1, sizeof(cli_list_t));
	if (!p)
		return -1;

	p->module_name = module_name;
	p->entry = entry;
	p->entry_count = count;
	p->next = *head;

	*head = p;
	return 0;
}

int cli_send_summary(FILE *out, cli_summary_t *cs)
{
	size_t n = 0;

	cs->version = CLI_SUMMARY_VERSION;
	n = fwrite(cs, sizeof(cli_summary_t), 1, out);
	if (n)
		fflush(out);
	return (!n);
}

cli_summary_t *cli_read_summary(FILE *in)
{
	cli_summary_t *cs;

	cs = calloc(1, sizeof(cli_summary_t));
	if (cs) {
		if (fread(cs, sizeof(cli_summary_t), 1, in)
		    && cs->version == CLI_SUMMARY_VERSION)
			return cs;
		free(cs);
	}
	return NULL;
}

int cli_socket_close(cli_socket_t *socket)
{
	if (socket->socket)
		usocket_close(socket->socket);
	free(socket);
	return 0;
}

cli_socket_t *cli_socket_init()
{
	cli_socket_t *cli_socket;

	cli_socket = calloc(1, sizeof(cli_socket_t));
	if (!cli_socket)
		return NULL;

	usocket_init();

	if (usocket_queue_init(&(cli_socket->queue)))
		return NULL;

	return cli_socket;
}

cli_socket_t *cli_socket_listen(char *sun_path)
{
	cli_socket_t *cli_socket;

	cli_socket = cli_socket_init();
	if (!cli_socket)
		return NULL;

	cli_socket->socket = usocket_create(sun_path);
	if (!cli_socket->socket) {
		cli_socket_close(cli_socket);
		return NULL;
	}

	if (usocket_listen(cli_socket->socket, 0)) {
		cli_socket_close(cli_socket);
		return NULL;
	}

	return cli_socket;
}

cli_socket_t *cli_socket_connect(char *sun_path)
{
	cli_socket_t *cli_socket;

	cli_socket = cli_socket_init();
	if (!cli_socket)
		return NULL;

	cli_socket->socket = usocket_connect(sun_path);
	if (!cli_socket->socket) {
		cli_socket_close(cli_socket);
		return NULL;
	}

	return cli_socket;
}

void cli_server_fini(cli_server_t *server)
{
	if (server->socket)
		cli_socket_close(server->socket);

	free(server);
}

cli_server_t *cli_server_init(char *sun_path)
{
	cli_server_t *server;
	cli_socket_t *socket;

	socket = cli_socket_listen(sun_path);
	if (!socket)
		return NULL;

	server = calloc(1, sizeof(cli_server_t));
	if (!server) {
		cli_socket_close(socket);
		return NULL;
	}

	server->socket = socket;

	usocket_register_handler(socket->socket, &cli_server_handler);
	usocket_queue_add(socket->queue, socket->socket, server);

	cli_register_entry(&(server->command_list), module_name,
	    cli_commands, CLI_ENTRY_COUNT(cli_commands));

	return server;
}

void cli_console_fini(cli_console_t *console)
{
	if (console->socket)
		cli_socket_close(console->socket);

	free(console);
}

cli_console_t *cli_console_init(char *sun_path)
{
	cli_console_t *console;
	cli_socket_t *socket;

	socket = cli_socket_connect(sun_path);
	if (!socket)
		return NULL;

	console = calloc(1, sizeof(cli_console_t));
	if (!console) {
		cli_socket_close(socket);
		return NULL;
	}

	console->socket = socket;

	usocket_register_handler(socket->socket, &cli_console_handler);
	usocket_queue_add(socket->queue, socket->socket, console);

	return console;
}
