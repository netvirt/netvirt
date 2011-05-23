#ifndef DNDS_ACLSET_H
#define DNDS_ACLSET_H

#include "ipset.h"

typedef struct jsw_rbtree aclset_t;

aclset_t *aclset_new();
void aclset_delete(aclset_t *aclset);
int aclset_insert(aclset_t *aclset, uint32_t id, ipset_t *ipset);
int aclset_erase(aclset_t *aclset, uint32_t id);
ipset_t *aclset_find(aclset_t *aclset, uint32_t id);
void aclset_printset(aclset_t *aclset);

#endif /* DNDS_ACLSET_H */
