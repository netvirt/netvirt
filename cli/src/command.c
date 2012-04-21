/*
 * command.c: Command prompt
 * Copyright 2012. Jamael Seun
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <dnds/cli.h>
#include <dnds/event.h>
#include <dnds/journal.h>
#include <dnds/usocket.h>
#include <dnds/xsched.h>

#include "command.h"
#include "linenoise.h"

static int prompt_wait = 0;

static void close_socket(usocket_t *);
static void read_socket(usocket_t *);
static usocket_handler_t command_socket_handler = {
	.recv = read_socket,
	.close = close_socket,
};

static command_list_t *command_list_head = NULL;

static void autocomplete(const char *buf, linenoiseCompletions *lc)
{
	command_list_t *p;

	for (p = command_list_head; p != NULL; p = p->next)
		if (strncmp(buf, p->command, strlen(buf)) == 0)
			linenoiseAddCompletion(lc, p->command);
}

static void register_command(char *cmd, size_t len)
{
	struct command_list *c;

	/* trash end of line marker */
	cmd[len-1] = '\0';

	c = calloc(1, sizeof(struct command_list));
	if (!c) {
		JOURNAL_ERR("could not create entry for `%s'", cmd);
		return;
	}
	strncpy(c->command, cmd, CLICMDSIZ);
	c->next = command_list_head;
	command_list_head = c;
}

static void free_command_list()
{
	command_list_t *p;

	for (p = command_list_head; p != NULL; p = p->next)
		free(p);

	command_list_head = NULL;
}

static void process_command_list(usocket_t *su)
{
	cli_summary_t *cs;

	cli_read_buffer(su->buf, register_command);
	cs = cli_read_summary(su->buf);
	if (cs) {
		if (cs->retval != CLI_RETURN_SUCCESS)
			JOURNAL_ERR("server failed to send command list");
		free(cs);
	} else
		JOURNAL_ERR("unexpected error while fetching commands");

	command_socket_handler.recv = read_socket;
	prompt_wait--;
}

static int local_command(char *line)
{
	if (!strcmp(line, ".quit")) {
		event_throw(EVENT_EXIT, NULL);
	}

	return 0;
}

static int remote_command(char *line, cli_socket_t *cli_socket)
{
	cli_summary_t cs = { 0 };
	struct command_list *e;
	size_t cmdlen = 0, linelen = 0;

	linelen = strlen(line);
	for (e = command_list_head; e != NULL; e = e->next) {
		cmdlen = strlen(e->command);
		if (strncmp(line, e->command, cmdlen) == 0) {
			if (cmdlen == linelen) {
				/* perfect match, no args */
				strncpy(cs.command, line, cmdlen);
				break;
			} else if (linelen > cmdlen && isblank(line[cmdlen])) {
				/* arguments might be present */
				strncpy(cs.args, line + cmdlen + 1, CLIARGSSIZ);
				strncpy(cs.command, line, cmdlen);
				break;
			} 
			/* not quite the perfect match */
			continue;
		}
	}

	if (!e) { /* command is not known */
		strncpy(cs.command, line, CLICMDSIZ);
	}

	if (cli_send_summary(cli_socket->socket->buf, &cs))
		return -1;

	prompt_wait++;
	return 0;
}

#define COMMAND_PROMPT "dndscli> "
static void prompt(void *udata)
{
	cli_socket_t *cli_socket = NULL;
	char *line;

	assert(udata != NULL);
	cli_socket = udata;

	if (prompt_wait)
		return;

	line = linenoise(COMMAND_PROMPT);
	if (line != NULL && line[0] != '\0') {
		linenoiseHistoryAdd(line);
		if (!local_command(line)
		    && remote_command(line, cli_socket)) {
			JOURNAL_ERR("unable to send command to remote target");
			free(line);
			return;
		}
	}
	free(line);
}

static void print_buffer(char *buf, size_t buflen)
{
	printf("%s", buf);
}

static void read_socket(usocket_t *su)
{
	cli_summary_t *cs;

	if (cli_read_buffer(su->buf, print_buffer))
		prompt_wait--;

	cs = cli_read_summary(su->buf);
	if (cs) {
		switch (cs->retval) {
		case CLI_RETURN_INVALID:
			JOURNAL_ERR("unknown command `%s'", cs->command);
			break;
		case CLI_RETURN_SHUTDOWN:
			prompt_wait++;
			break;
		}
		free(cs);
	}
}

static void close_socket(usocket_t *su)
{
	cli_console_t *console = su->udata;

	assert(su != NULL);
	usocket_close(su);
	console->socket->socket = NULL;

	event_throw(EVENT_EXIT, NULL);
}

static void fini(void *udata)
{
	free_command_list();
}

void command_set_completion()
{
	linenoiseSetCompletionCallback(autocomplete);
}

int command_list_fetch(cli_socket_t *cli_socket)
{
	cli_summary_t cs = { .command = "list" };
	command_socket_handler.recv = process_command_list;

	if (cli_send_summary(cli_socket->socket->buf, &cs))
		return -1;

	prompt_wait++;
	return 0;
}

int command_init(cli_socket_t *cli_socket)
{
	usocket_register_handler(cli_socket->socket, &command_socket_handler);
	event_register(EVENT_EXIT, "command:fini()", fini, PRIO_HIGH);
	sched_register(SCHED_APERIODIC, "prompt", prompt, 0, cli_socket);

	return 0;
}
