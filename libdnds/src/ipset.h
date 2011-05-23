#ifndef DNDS_IPSET_H
#define DNDS_IPSET_H

typedef struct jsw_rbtree ipset_t;

ipset_t *ipset_new();
void ipset_delete(ipset_t *ipset);
int ipset_insert(ipset_t *ipset, const char *ip);
int ipset_erase(ipset_t *ipset, const char *ip);
int ipset_find(ipset_t *ipset, const char *ip);
void ipset_printset(ipset_t *ipset);

#endif /* DNDS_IPSET_H */
