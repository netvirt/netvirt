/*
 * setx.c: STX/ETX buffer protocol
 * Copyright 2012. The OpenDNDS team. <team@opendnds.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "setx.h"

/**
 * setx_read_buffer() gets one char first looking for markers.
 * If the STX marker is found, it reads lines contained inside
 * the boundaries of STX and ETX marker calling `p' callback
 * for each successful iteration.
 *
 *	+-----+-----+-----+-----+
 *	| STX | ... | EOL | ETX |
 *	+-----+-----+-----+-----+
 *
 * NOTE: setx_read_buffer() blocks until ETX marker is found.
 */
int setx_read_buffer(FILE *in, void (*p)(char *, size_t))
{
	char line[SETXLINESIZ];
	size_t n;
	int c, z, stx_found = 0;

	while ((c = fgetc(in)) != EOF) {
		switch (c) {
		case STX:	/* start of text marker */
			stx_found = 1;
			continue;
		case EOL:	/* end of line marker */
			if ((z = fgetc(in)) == ETX) 
				return SETX_READ_OK;
			ungetc(z, in);
			break;
		case ETX:	/* end of text marker */
			return SETX_READ_OK;
		}

		ungetc(c, in);
		if (stx_found) {
			if (fgets(line, SETXLINESIZ, in)) {
				p(line, strlen(line));
				continue;
			}
		}
		break; /* STX must start the buffer */
	}
	return SETX_READ_FAIL;
}
