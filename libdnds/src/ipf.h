#ifndef DNDS_IPF_H
#define DNDS_IPF_H

typedef struct ipf ipf_t;

ipf_t *ipf_new();
void ipf_del(ipf_t *ipf);
int ipf_rule_append(ipf_t *ipf, ipset_t *ipset_src, ipset_t *ipset_dst, uint8_t verdict);
int ipf_rule_del(ipf_t *ipf, ipset_t *ipset_src, ipset_t *ipset_dst, uint8_t verdict);
void ipf_default_policy(ipf_t *ipf, uint8_t verdict);
uint8_t ipf_filter(ipf_t *ipf, const char *ip_src, const char *ip_dst);

#endif /* DNDS_IPF_H */
