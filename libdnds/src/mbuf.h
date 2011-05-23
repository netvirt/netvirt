#ifndef MBUF_H
#define MBUF_H

#include <stdint.h>
#include <sys/types.h>

#define MBUF_BYVAL	0x1		// copy the data
#define MBUF_BYREF	0x2		// reference the data, usefull with data not serialized

typedef struct mbuf {

	struct mbuf *next;		// next mbuf
	struct mbuf *prev;		// prev mbuf

	size_t count;			// the number of element

	uint8_t mem_type;		// memory type [MBUF_BYVAL, MBUF_BYREF]

	uint8_t *ext_buf;		// start of buffer
	uint32_t ext_size;		// size of buffer

	void (*free)(void *ext_buf);	// external free, use with MBUF_BYREF

} mbuf_t;

int mbuf_count(mbuf_t *mbuf_head);
int mbuf_add(mbuf_t **, mbuf_t *);
int mbuf_del(mbuf_t **, mbuf_t *);
mbuf_t *mbuf_new(const void *buf, size_t data_size, uint8_t mem_type, void (*free)(void *));

#endif /* MBUF_H */
