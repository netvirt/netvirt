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

#include "logger.h"

FILE *log_file = NULL;

void jlog_init_file(const char *log_file_path)
{
	log_file = fopen(log_file_path, "a");
}

void jlog(int level, const char *format, ...)
{
	char logline[256];

	va_list ap;
	va_start(ap, format);

	snprintf(logline, 256, "%s\n", format);
	if (log_file) {
		vfprintf(log_file, logline, ap);
		fflush(log_file);
	}
	else {
		vfprintf(stdout, logline, ap);
	}
	va_end(ap);
}
