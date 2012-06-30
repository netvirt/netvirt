#ifndef DNDS_JOURNAL_H
#define DNDS_JOURNAL_H

#define L_NOTICE	0x01
#define L_WARNING	0x02
#define L_ERROR		0x04
#define L_DEBUG		0x08

void jlog(int level, char *format, ...);

#endif
