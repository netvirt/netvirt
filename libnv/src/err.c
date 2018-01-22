#include <stdarg.h>

extern char *__progname = "netvirt";
void openlog(const char *ident, int option, int facility) {}
void vsyslog(int priority, const char *format, va_list ap) {}

void warn (const char *fmt, ...) { }
void warnx (const char *fmt, ...) { }
void err (int eval, const char *fmt, ...) { }
void errx (int eval, const char *fmt, ...) { }
void vwarn (const char *fmt, va_list ap) { }
void vwarnx (const char *fmt, va_list ap) { }
void verr (int eval, const char *fmt, va_list ap) { }
void verrx (int eval, const char *fmt, va_list ap) { }


