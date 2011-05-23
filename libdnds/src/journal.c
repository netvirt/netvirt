/*
 * journal.c: Logging API
 *
 * Copyright (C) 2010 Mind4Networks
 * Author: Benjamin Vanheuverzwijn
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

#include "event.h"
#include "journal.h"
#include "utils.h"

#define LOGLINE_SIZE 256

static int journal_daemonized =  false;
static int journal_priority = LOG_DEBUG;

/*
 * Get priority name from the level constant
 * @param level Priority you want the printable name
 * @return Priority readable name
 */
static const char *journal_level2priorityname(int level)
{
	switch (level) {
		case LOG_EMERG:
			return "emerg";
		case LOG_ALERT:
			return "alert";
		case LOG_CRIT:
			return "critical";
		case LOG_ERR:
			return "error";
		case LOG_WARNING:
			return "warning";
		case LOG_NOTICE:
			return "notice";
		case LOG_INFO:
			return "info";
		case LOG_DEBUG:
			return "debug";
		default:
			return "unknown";
	}

	return "unknown";
}

/*
 * Write to the syslog daemon
 * @param level Message priority
 * @param format Format of the message
 * @param ap Variable arguments
 */
static void journal_write_syslog(int level, char *format, va_list ap)
{
	openlog("DNDS", LOG_PID, LOG_DAEMON);
	vsyslog(level, format, ap);
}

/*
 * Write to a file descriptor (default to stdout for now)
 * @param level Message priority
 * @param format Format of the message
 * @param ap Variable arguments
 */
static void journal_write_fd(int level, char *format, va_list ap)
{
	struct timeval now;
	const char *priorityname;
	char asciidate[22];
	char logline[LOGLINE_SIZE];
	time_t t;

	t = time(NULL);
	// "2010-12-31 - 23:25:59"
	strftime(asciidate, sizeof(asciidate), "%F - %T", localtime(&t));
	// see journal_level2priorityname
	priorityname = (const char *)journal_level2priorityname(level);

	snprintf(logline, LOGLINE_SIZE, "%s %s >>> %s\n", asciidate, priorityname, format);

	vfprintf(stdout, logline, ap);
}

/*
 * Print something to the journal at the specified level
 * @param level Priority of the message
 * @param format Format of the message (same as printf)
 * @return 0
 */
int journal_write(int level, char *format, ...)
{
	if (level <= journal_priority) {
		va_list ap;
		va_start(ap, format);

		if (journal_daemonized) {
			journal_write_syslog(level, format, ap);
		}
		else {
			journal_write_fd(level, format, ap);
		}

		va_end(ap);
	}

	return 0;
}

/*
 * Change the journal verbosity.
 * @param priority Everything with equal or greater priority will be printed
 * @return The previous priority
 */
int journal_set_priority(int priority)
{
	int old_priority = journal_priority;
	journal_priority = priority;
	return old_priority;
}

int journal_get_priority()
{
	return journal_priority;
}

void journal_set_lvl(int lvl)
{
	if (lvl == 1)
		journal_daemonized = true;
	else
		journal_daemonized = false;
}
