/*
  Hash table library using separate chaining

    > Created (Julienne Walker): August 7, 2005
    > Modified (Julienne Walker): August 11, 2005
      Added a cast for malloc to enable clean
      compilation as C++
*/
#include "jsw_hlib.h"

#ifdef __cplusplus
#include <cstdlib>

using std::malloc;
using std::free;
#else
#include <stdlib.h>
#endif

typedef struct jsw_node {
  void            *key;  /* Key used for searching */
  void            *item; /* Actual content of a node */
  struct jsw_node *next; /* Next link in the chain */
} jsw_node_t;

typedef struct jsw_head {
  jsw_node_t *first;     /* First link in the chain */
  size_t      size;      /* Length of the chain */
} jsw_head_t;

struct jsw_hash {
  jsw_head_t **table;    /* Dynamic chained hash table */
  size_t       size;     /* Current item count */
  size_t       capacity; /* Current table size */
  size_t       curri;    /* Current index for traversal */
  jsw_node_t  *currl;    /* Current link for traversal */
  hash_f       hash;     /* User defined key hash function */
  cmp_f        cmp;      /* User defined key comparison function */
  keydup_f     keydup;   /* User defined key copy function */
  itemdup_f    itemdup;  /* User defined item copy function */
  keyrel_f     keyrel;   /* User defined key delete function */
  itemrel_f    itemrel;  /* User defined item delete function */
};

static jsw_node_t *new_node ( void *key, void *item, jsw_node_t *next )
{
  jsw_node_t *node = (jsw_node_t *)malloc ( sizeof *node );

  if ( node == NULL )
    return NULL;

  node->key = key;
  node->item = item;
  node->next = next;

  return node;
}

static jsw_head_t *new_chain ( void )
{
  jsw_head_t *chain = (jsw_head_t *)malloc ( sizeof *chain );

  if ( chain == NULL )
    return NULL;

  chain->first = NULL;
  chain->size = 0;

  return chain;
}

/*
  Create a new hash table with a capacity of size, and
  user defined functions for handling keys and items.

  Returns: An empty hash table, or NULL on failure.
*/
jsw_hash_t  *jsw_hnew ( size_t size, hash_f hash, cmp_f cmp,
  keydup_f keydup, itemdup_f itemdup,
  keyrel_f keyrel, itemrel_f itemrel )
{
  jsw_hash_t *htab = (jsw_hash_t *)malloc ( sizeof *htab );
  size_t i;

  if ( htab == NULL )
    return NULL;

  htab->table = (jsw_head_t **)malloc ( size * sizeof *htab->table );

  if ( htab->table == NULL ) {
    free ( htab );
    return NULL;
  }

  /* Empty chains have no head */
  for ( i = 0; i < size; i++ )
    htab->table[i] = NULL;

  htab->size = 0;
  htab->capacity = size;
  htab->curri = 0;
  htab->currl = NULL;
  htab->hash = hash;
  htab->cmp = cmp;
  htab->keydup = keydup;
  htab->itemdup = itemdup;
  htab->keyrel = keyrel;
  htab->itemrel = itemrel;

  return htab;
}

/* Release all memory used by the hash table */
void jsw_hdelete ( jsw_hash_t *htab )
{
  size_t i;

  /* Release each chain individually */
  for ( i = 0; i < htab->capacity; i++ ) {
    jsw_node_t *save, *it;

    if ( htab->table[i] == NULL )
      continue;

    it = htab->table[i]->first;

    for ( ; it != NULL; it = save ) {
      save = it->next;
      htab->keyrel ( it->key );
      htab->itemrel ( it->item );
      free ( it );
    }

    free ( htab->table[i] );
  }

  /* Release the hash table */
  free ( htab->table );
  free ( htab );
}

/*
  Find an item with the selected key

  Returns: The item, or NULL if not found
*/
void *jsw_hfind ( jsw_hash_t *htab, void *key )
{
  unsigned h = htab->hash ( key ) % htab->capacity;

  /* Search the chain only if it exists */
  if ( htab->table[h] != NULL ) {
    jsw_node_t *it = htab->table[h]->first;

    for ( ; it != NULL; it = it->next ) {
      if ( htab->cmp ( key, it->key ) == 0 )
        return it->item;
    }
  }

  return NULL;
}

/*
  Insert an item with the selected key

  Returns: non-zero for success, zero for failure
*/
int jsw_hinsert ( jsw_hash_t *htab, void *key, void *item )
{
  unsigned h = htab->hash ( key ) % htab->capacity;
  void *dupkey, *dupitem;
  jsw_node_t *new_item;

  /* Disallow duplicate keys */
  if ( jsw_hfind ( htab, key ) != NULL )
    return 0;

  /* Attempt to create a new item */
  dupkey = htab->keydup ( key );
  dupitem = htab->itemdup ( item );

  new_item = new_node ( dupkey, dupitem, NULL );

  if ( new_item == NULL )
    return 0;

  /* Create a chain if the bucket is empty */
  if ( htab->table[h] == NULL ) {
    htab->table[h] = new_chain();

    if ( htab->table[h] == NULL ) {
      htab->keyrel ( new_item->key );
      htab->itemrel ( new_item->item );
      free ( new_item );
      return 0;
    }
  }

  /* Insert at the front of the chain */
  new_item->next = htab->table[h]->first;
  htab->table[h]->first = new_item;

  ++htab->table[h]->size;
  ++htab->size;

  return 1;
}

/*
  Remove an item with the selected key

  Returns: non-zero for success, zero for failure
*/
int jsw_herase ( jsw_hash_t *htab, void *key )
{
  unsigned h = htab->hash ( key ) % htab->capacity;
  jsw_node_t *save, *it;

  if ( htab->table[h] == NULL )
    return 0;

  it = htab->table[h]->first;

  /* Remove the first node in the chain? */
  if ( htab->cmp ( key, it->key ) == 0 ) {
    htab->table[h]->first = it->next;

    /* Release the node's memory */
    htab->keyrel ( it->key );
    htab->itemrel ( it->item );
    free ( it );

    /* Remove the chain if it's empty */
    if ( htab->table[h]->first == NULL ) {
      free ( htab->table[h] );
      htab->table[h] = NULL;
    }
    else
      --htab->table[h]->size;
  }
  else {
    /* Search for the node */
    while ( it->next != NULL ) {
      if ( htab->cmp ( key, it->next->key ) == 0 )
        break;

      it = it->next;
    }

    /* Not found? */
    if ( it->next == NULL )
      return 0;

    save = it->next;
    it->next = it->next->next;

    /* Release the node's memory */
    htab->keyrel ( save->key );
    htab->itemrel ( save->item );
    free ( save );

    --htab->table[h]->size;
  }

  /* Erasure invalidates traversal markers */
  jsw_hreset ( htab );

  --htab->size;

  return 1;
}

/*
  Grow or shrink the table, this is a slow operation
  
  Returns: non-zero for success, zero for failure
*/
int jsw_hresize ( jsw_hash_t *htab, size_t new_size )
{
  jsw_hash_t *new_htab;
  jsw_node_t *it;
  size_t i;

  /* Build a new hash table, then assign it to the old one */
  new_htab = jsw_hnew ( new_size, htab->hash, htab->cmp,
    htab->keydup, htab->itemdup, htab->keyrel, htab->itemrel );

  if ( new_htab == NULL )
    return 0;

  for ( i = 0; i < htab->capacity; i++ ) {
    if ( htab->table[i] == NULL )
      continue;

    for ( it = htab->table[i]->first; it != NULL; it = it->next )
      jsw_hinsert ( new_htab, it->key, it->item );
  }

  /* A hash table holds copies, so release the old table */
  jsw_hdelete ( htab );
  htab = new_htab;

  return 1;
}

/* Reset the traversal markers to the beginning */
void jsw_hreset ( jsw_hash_t *htab )
{
  size_t i;

  htab->curri = 0;
  htab->currl = NULL;

  /* Find the first non-empty bucket */
  for ( i = 0; i < htab->capacity; i++ ) {
    if ( htab->table[i] != NULL )
      break;
  }

  htab->curri = i;

  /* Set the link marker if the table was not empty */
  if ( i != htab->capacity )
    htab->currl = htab->table[i]->first;
}

/* Traverse forward by one key */
int jsw_hnext ( jsw_hash_t *htab )
{
  if ( htab->currl != NULL ) {
    htab->currl = htab->currl->next;

    /* At the end of the chain? */
    if ( htab->currl == NULL ) {
      /* Find the next chain */
      while ( ++htab->curri < htab->capacity ) {
        if ( htab->table[htab->curri] != NULL )
          break;
      }

      /* No more chains? */
      if ( htab->curri == htab->capacity )
        return 0;

      htab->currl = htab->table[htab->curri]->first;
    }
  }

  return 1;
}

/* Get the current key */
const void *jsw_hkey ( jsw_hash_t *htab )
{
  return htab->currl != NULL ? htab->currl->key : NULL;
}

/* Get the current item */
void *jsw_hitem ( jsw_hash_t *htab )
{
  return htab->currl != NULL ? htab->currl->item : NULL;
}

/* Current number of items in the table */
size_t jsw_hsize ( jsw_hash_t *htab )
{
  return htab->size;
}

/* Total allowable number of items without resizing */
size_t jsw_hcapacity ( jsw_hash_t *htab )
{
  return htab->capacity;
}

/* Get statistics for the hash table */
jsw_hstat_t *jsw_hstat ( jsw_hash_t *htab )
{
  jsw_hstat_t *stat;
  double sum = 0, used = 0;
  size_t i;

  /* No stats for an empty table */
  if ( htab->size == 0 )
    return NULL;

  stat = (jsw_hstat_t *)malloc ( sizeof *stat );

  if ( stat == NULL )
    return NULL;

  stat->lchain = 0;
  stat->schain = (size_t)-1;

  for ( i = 0; i < htab->capacity; i++ ) {
    if ( htab->table[i] != NULL ) {
      sum += htab->table[i]->size;

      ++used; /* Non-empty buckets */

      if ( htab->table[i]->size > stat->lchain )
        stat->lchain = htab->table[i]->size;

      if ( htab->table[i]->size < stat->schain )
        stat->schain = htab->table[i]->size;
    }
  }

  stat->load = used / htab->capacity;
  stat->achain = sum / used;

  return stat;
}
