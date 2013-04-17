#ifndef DNDS_UTILS_H
#define DNDS_UTILS_H

#include <stdint.h>

extern int daemonize();
extern char *trim(char *str);

#define true 1
#define false !true

#endif /* DNDS_UTILS_H */
