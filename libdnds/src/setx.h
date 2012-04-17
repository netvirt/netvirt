/*
 * setx.h: STX/ETX buffer protocol
 * Copyright 2012. The OpenDNDS team. <team@opendnds.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */
#ifndef DNDS_SETX_H
#define DNDS_SETX_H

#include <stdio.h>

#define STX 0x02
#define ETX 0x03
#define EOL 0x0A

#define SETXLINESIZ 1024

#define SETX_READ_OK 1
#define SETX_READ_FAIL 0

static inline void setx_begin(FILE *buf) {
	fputc(STX, buf);
}
static inline int setx_end(FILE *buf) {
	fputc(EOL, buf);
	fputc(ETX, buf);
	fflush(buf);
}

extern int setx_read_buffer(FILE *, void (*)(char *, size_t));

#endif /* DNDS_SETX_H */
