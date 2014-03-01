/*
 * Logging journal
 *
 * Copyright (C) 2012 Nicolas Bouliane
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "logger.h"

FILE *log_file = NULL;
void (*on_log_cb)(const char *str) = NULL;

void jlog_init_cb(void (*on_log)(const char *str))
{
	on_log_cb = on_log;
}

void jlog_init_file(const char *log_file_path)
{
	log_file = fopen(log_file_path, "a");
}

void jlog(int level, const char *format, ...)
{
	char logline[256];
	static char logtxt[512];
	time_t timer;
	char cur_time[20];
	struct tm* tm_info;

	va_list ap;
	va_start(ap, format);

	time(&timer);
	tm_info = localtime(&timer);
	strftime(cur_time, 20, "%F %H:%M:%S", tm_info);

	snprintf(logline, 256, "[%s] %s\n", cur_time, format);

	if (on_log_cb) {
		vsnprintf(logtxt, 512, logline, ap);
		on_log_cb(logtxt);
	}
	if (log_file) {
		vfprintf(log_file, logline, ap);
		fflush(log_file);
	}
	else {
		vfprintf(stdout, logline, ap);
	}
	va_end(ap);
}
