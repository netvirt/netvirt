#ifndef DNDS_JOURNAL_H
#define DNDS_JOURNAL_H

#include <syslog.h>

#define EXIT_ERR	0x0001 /* default error */ 
#define EXIT_NOT_ROOT	0x0002
#define EXIT_NO_MYSQL	0x0004
#define EXIT_ERR_PARS	0x0006
#define TRUM_ERR	0x0008

#define ERR_NULPL	0x0001
#define ERR_ACL		0x0002

#define JOURNAL_EMERG(...) journal_write(LOG_EMERG, __VA_ARGS__)
#define JOURNAL_ALERT(...) journal_write(LOG_ALERT, __VA_ARGS__)
#define JOURNAL_CRIT(...) journal_write(LOG_CRIT, __VA_ARGS__)
#define JOURNAL_ERR(...) journal_write(LOG_ERR, __VA_ARGS__)
#define JOURNAL_WARN(...) journal_write(LOG_WARNING, __VA_ARGS__)
#define JOURNAL_NOTICE(...) journal_write(LOG_NOTICE, __VA_ARGS__)
#define JOURNAL_INFO(...) journal_write(LOG_INFO, __VA_ARGS__)
#define JOURNAL_DEBUG(...) journal_write(LOG_DEBUG, __VA_ARGS__)

extern int journal_write(int priority, char *format, ...);
extern int journal_get_priority();
extern int journal_set_priority(int);
extern void journal_set_lvl(int);

#endif /* DNDS_JOURNAL_H */
