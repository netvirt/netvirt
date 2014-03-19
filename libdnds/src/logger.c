/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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

void _jlog(const char *file, int line, int level, const char *format, ...)
{
	char logline[256];
	static char logtxt[512];
	time_t timer;
	char cur_time[20];
	struct tm* tm_info;
	const char *filename = NULL;

	(void)(level); /* unused */

	va_list ap;
	va_start(ap, format);

	time(&timer);
	tm_info = localtime(&timer);
	strftime(cur_time, 20, "%Y-%m-%d %H:%M:%S", tm_info);

	filename = strrchr(file, '/') ? strrchr(file, '/') + 1: file;

	snprintf(logline, 256, "[%s] %s:%d]> %s\n", cur_time, filename, line, format);
	vsnprintf(logtxt, 512, logline, ap);
	va_end(ap);

	if (on_log_cb) {
		on_log_cb(logtxt);
	}
	if (log_file) {
		fprintf(log_file, "%s", logtxt);
		fflush(log_file);
	}
}
