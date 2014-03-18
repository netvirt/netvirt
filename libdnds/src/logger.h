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

#ifndef DNDS_JOURNAL_H
#define DNDS_JOURNAL_H

#define L_NOTICE	0x01
#define L_WARNING	0x02
#define L_ERROR		0x04
#define L_DEBUG		0x08

#ifdef __cplusplus
extern "C" {
#endif

void jlog_init_cb(void (*on_log)(const char *str));
void jlog_init_file(const char *log_file_path);
void jlog(int level, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
