#ifndef DNDS_BITPOOL_H
#define DNDS_BITPOOL_H

int bitpool_release_bit(uint8_t bitpool[], size_t nbits, uint32_t bit);
int bitpool_allocate_bit(uint8_t bitpool[], size_t nbits, uint32_t *bit);
void bitpool_free(uint8_t *bitpool);
int bitpool_new(uint8_t **bitpool, size_t nbits);

#endif
