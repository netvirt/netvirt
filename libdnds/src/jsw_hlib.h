#ifndef JSW_HLIB
#define JSW_HLIB

/*
  Hash table library using separate chaining

    > Created (Julienne Walker): August 7, 2005
    > Modified (Julienne Walker): August 11, 2005

  This code is in the public domain. Anyone may
  use it or change it in any way that they see
  fit. The author assumes no responsibility for 
  damages incurred through use of the original
  code or any variations thereof.

  It is requested, but not required, that due
  credit is given to the original author and
  anyone who has modified the code through
  a header comment, such as this one.
*/
#ifdef __cplusplus
#include <cstddef>

using std::size_t;

extern "C" {
#else
#include <stddef.h>
#endif

typedef struct jsw_hash jsw_hash_t;

/* Application specific hash function */
typedef unsigned (*hash_f) ( const void *key );

/* Application specific key comparison function */
typedef int      (*cmp_f) ( const void *a, const void *b );

/* Application specific key copying function */
typedef void    *(*keydup_f) ( const void *key );

/* Application specific data copying function */
typedef void    *(*itemdup_f) ( const void *item );

/* Application specific key deletion function */
typedef void     (*keyrel_f) ( void *key );

/* Application specific data deletion function */
typedef void     (*itemrel_f) ( void *item );

typedef struct jsw_hstat {
  double load;            /* Table load factor: (M chains)/(table size) */
  double achain;          /* Average chain length */
  size_t lchain;          /* Longest chain */
  size_t schain;          /* Shortest non-empty chain */
} jsw_hstat_t;

/*
  Create a new hash table with a capacity of size, and
  user defined functions for handling keys and items.

  Returns: An empty hash table, or NULL on failure.
*/
jsw_hash_t  *jsw_hnew ( size_t size, hash_f hash, cmp_f cmp,
                       keydup_f keydup, itemdup_f itemdup,
                       keyrel_f keyrel, itemrel_f itemrel );

/* Release all memory used by the hash table */
void         jsw_hdelete ( jsw_hash_t *htab );

/*
  Find an item with the selected key

  Returns: The item, or NULL if not found
*/
void        *jsw_hfind ( jsw_hash_t *htab, void *key );

/*
  Insert an item with the selected key

  Returns: non-zero for success, zero for failure
*/
int          jsw_hinsert ( jsw_hash_t *htab, void *key, void *item );

/*
  Remove an item with the selected key

  Returns: non-zero for success, zero for failure
*/
int          jsw_herase ( jsw_hash_t *htab, void *key );

/*
  Grow or shrink the table, this is a slow operation
  
  Returns: non-zero for success, zero for failure
*/
int          jsw_hresize ( jsw_hash_t *htab, size_t new_size );

/* Reset the traversal markers to the beginning */
void         jsw_hreset ( jsw_hash_t *htab );

/* Traverse forward by one key */
int          jsw_hnext ( jsw_hash_t *htab );

/* Get the current key */
const void  *jsw_hkey ( jsw_hash_t *htab );

/* Get the current item */
void        *jsw_hitem ( jsw_hash_t *htab );

/* Current number of items in the table */
size_t       jsw_hsize ( jsw_hash_t *htab );

/* Total allowable number of items without resizing */
size_t       jsw_hcapacity ( jsw_hash_t *htab );

/* Get statistics for the hash table */
jsw_hstat_t *jsw_hstat ( jsw_hash_t *htab );

#ifdef __cplusplus
}
#endif

#endif
