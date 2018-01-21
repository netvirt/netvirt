#ifndef _ERR_H
#define _ERR_H

#include <sys/cdefs.h>
#include <stdarg.h>

extern void warn (const char *fmt, ...);
extern void warnx (const char *fmt, ...);

extern void err (int eval, const char *fmt, ...);
extern void errx (int eval, const char *fmt, ...);

extern void vwarn (const char *fmt, va_list ap);
extern void vwarnx (const char *fmt, va_list ap);

extern void verr (int eval, const char *fmt, va_list ap);
extern void verrx (int eval, const char *fmt, va_list ap);

#endif /* _ERR_H */
