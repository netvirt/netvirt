#ifndef DNDS_UTILS_H
#define DNDS_UTILS_H

#include <stdint.h>

#define PATHLEN 256

extern int daemonize();

extern int bv_set(const unsigned int, uint8_t *, const unsigned int);
extern int bv_unset(const unsigned int, uint8_t *, const unsigned int);
extern int bv_test(const unsigned int, uint8_t *, const unsigned int);

extern int alloc_bitmap(size_t bits, uint8_t **bitmap);
extern int allocate_bit(uint8_t bitmap[], size_t bits, uint32_t *bit);
extern int free_bit(uint8_t bitmap[], size_t bits, size_t bit);

extern char *trim(char *str);
extern char *x_strtok(char **, char **, char);

extern int swap_context(char *, const unsigned int);
extern char *x509_get_cn(char *);

typedef int int_vector;

#define VECTOR_IDX_SIZE 0
#define VECTOR_IDX_MAX 1
#define VECTOR_IDX_BEGIN 2
#define VECTOR_SET_MAX(n) (n + VECTOR_IDX_BEGIN + VECTOR_IDX_MAX)
#define VECTOR_SET_SIZE(n) (n - VECTOR_IDX_BEGIN)


#define true 1
#define false !true

#endif /* DNDS_UTILS_H */
