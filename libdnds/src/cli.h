/*
 * cli.h: Command line interface API
 * Copyright 2012. Jamael Seun
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#ifndef DNDS_CLI_H
#define DNDS_CLI_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "setx.h"
#include "usocket.h"

#define CLI_INIT 1
#define CLI_EXEC 2

#define CLI_RETURN_SUCCESS 0		/* command returned success */
#define CLI_RETURN_FAILURE 1		/* command returned failure */
#define CLI_RETURN_INVALID 2		/* command is not valid */
#define CLI_RETURN_SHUTDOWN 3		/* cli is closing socket */
#define CLI_RETURN_SHOWUSAGE 4		/* misusage of command */

enum CLIARGSPE {
	CLIARGPEMAR = 1,	/* max arguments reached */
	CLIARGPEBBQ,		/* no blank before quote */
	CLIARGPENEQ,		/* no end quote */

	CLIARGSPE_COUNT		/* must be last one */
};

typedef struct cli_entry cli_entry_t;
typedef struct cli_list cli_list_t;

#define CLICMDSIZ 32
#define CLIARGSSIZ 128
#define CLIARGVSIZ 12
typedef struct {
	int fd;				/* remote socket file descriptor */
	FILE *out;			/* opened socket stream to remote */
	cli_list_t *command_list;	/* command list head */
	char args[CLIARGSSIZ];		/* arguments slot */
	char *argv[CLIARGVSIZ];		/* argument line */
	int argc;			/* argument count */
	int perror;			/* parsing error */
	int pe_near;			/* parsing error position */
} cli_args_t;

static inline char *cli_args_perror(int pe_num)
{
	static char *perr[CLIARGSPE_COUNT] = {
		"max arguments reached",
		"no blank before quote",
		"missing end quote",
	};
	return (pe_num < CLIARGSPE_COUNT) ? perr[pe_num - 1] : NULL;
}

struct cli_entry {
	char *command;			/* command name */
	char *usage;			/* command usage notice */
	char *desc;			/* command description */
	int (*handler)(cli_entry_t *, int, cli_args_t *); /* command handler */
};

struct cli_list{
	cli_list_t *next;		/* linked list */

	char const *module_name;	/* name of module */
	cli_entry_t *entry;		/* command entries */
	size_t entry_count;		/* number of entries */
};

#define CLI_ENTRY_COUNT(e) (size_t)(sizeof((e)) / sizeof(*(e)))
#define CLI_ENTRY(h, d) { .handler = (h), .desc = (d) }

typedef struct {
	usocket_t *socket;
	int queue;
} cli_socket_t;

typedef struct {
	cli_socket_t *socket;
	cli_list_t *command_list;
} cli_server_t;

typedef struct {
	cli_socket_t *socket;
} cli_console_t;

#define CLI_SUMMARY_VERSION 1
typedef struct {
	uint8_t version;			/* version */
	uint8_t retval;				/* command return value */
	char command[CLICMDSIZ];		/* command name */
	char args[CLIARGSSIZ];			/* command arguments */
} cli_summary_t;

#define cli_buffer_start(buf) setx_begin(buf)
#define cli_buffer_end(buf) setx_end(buf)
#define cli_print(buf, ...) fprintf(buf, __VA_ARGS__)

static inline
int cli_read_buffer(FILE *buf, void (*p)(char *, size_t))
{
	return (setx_read_buffer(buf, p) == SETX_READ_OK);
}

extern int cli_exec(cli_summary_t *, cli_args_t *, cli_list_t *);
extern cli_entry_t *cli_find_entry(char *, cli_list_t *);
extern void cli_free_entry_all(cli_list_t **);
extern int cli_register_entry(cli_list_t **, char const *, cli_entry_t *, size_t);
extern cli_summary_t *cli_read_summary(FILE *);
extern int cli_send_summary(FILE *, cli_summary_t *);
extern int cli_print_usage(FILE *, cli_entry_t *);

extern int cli_socket_close(cli_socket_t *);
extern cli_socket_t *cli_socket_init();
extern cli_socket_t *cli_socket_listen(char *);
extern cli_socket_t *cli_socket_connect(char *);

extern void cli_server_fini(cli_server_t *);
extern cli_server_t *cli_server_init(char *);
extern void cli_console_fini(cli_console_t *);
extern cli_console_t *cli_console_init(char *);

#endif /* DNDS_CLI_H */
