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

void jlog(int level, char *format, ...)
{
	char logline[256];

	va_list ap;
	va_start(ap, format);

	snprintf(logline, 256, "%s\n", format);
	vfprintf(stdout, logline, ap);
	va_end(ap);
}
